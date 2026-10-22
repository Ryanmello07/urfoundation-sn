package miner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Releases of urnetwork/build carry SHA256SUMS (sha256sum format) and
// SHA256SUMS.sig, signed on the release machine with a key that never leaves
// it (ECDSA P-256, in the Mac's Secure Enclave). Once a key is pinned here,
// an update installs a download only when SHA256SUMS lists it with the same
// digest the release does, and one of the pinned keys signed SHA256SUMS for
// this release's tag. A stolen GitHub token can publish a release, but
// can't sign one.
//
// Two keys are pinned: the release machine's, and a backup kept offline
// that signs a release pinning a new key when the first is lost.

// minerReleaseKeys are the pinned public keys, PKIX DER in base64. Until
// one is pinned, releases are checked against the digests GitHub lists only.
var minerReleaseKeys = []string{}

const minerReleaseSumsName = "SHA256SUMS"
const minerReleaseSignatureName = "SHA256SUMS.sig"

// The signature covers this context line, the tag and SHA256SUMS, so a
// signed SHA256SUMS can't be replayed under another tag.
const minerReleaseSignatureContext = "urnetwork release signature v1\n"

const minerReleaseSumsMax = 1 << 20

func minerReleaseSignedMessage(tag string, sums []byte) []byte {
	message := []byte(minerReleaseSignatureContext + "tag " + tag + "\n")
	return append(message, sums...)
}

func parseMinerReleaseKeys(encoded []string) ([]*ecdsa.PublicKey, error) {
	var keys []*ecdsa.PublicKey
	for _, value := range encoded {
		der, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok || key.Curve.Params().Name != "P-256" {
			return nil, errors.New("a pinned release key isn't ECDSA P-256")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// verifyMinerReleaseSignature checks the release's signed SHA256SUMS for
// the asset, when a release key is pinned.
func verifyMinerReleaseSignature(ctx context.Context, release *minerRelease, asset *minerReleaseAsset, digest string) error {
	keys, err := parseMinerReleaseKeys(minerReleaseKeys)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	sums, err := readMinerReleaseFile(ctx, release, minerReleaseSumsName)
	if err != nil {
		return err
	}
	signature, err := readMinerReleaseFile(ctx, release, minerReleaseSignatureName)
	if err != nil {
		return err
	}
	return checkMinerReleaseSignature(keys, release.TagName, sums, signature, asset.Name, digest)
}

func readMinerReleaseFile(ctx context.Context, release *minerRelease, name string) ([]byte, error) {
	for _, asset := range release.Assets {
		if asset.Name != name {
			continue
		}
		if _, test := minerUpdateSource(); !test && !minerTrustedDownload(asset.Url) {
			return nil, fmt.Errorf("release %s points %s outside GitHub (%s)", release.TagName, name, minerHost(asset.Url))
		}
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		body, err := minerOpen(ctx, asset.Url, release.base)
		if err != nil {
			return nil, err
		}
		defer body.Close()
		return io.ReadAll(io.LimitReader(body, minerReleaseSumsMax))
	}
	return nil, fmt.Errorf("release %s isn't signed (it has no %s); nothing was changed", release.TagName, name)
}

// checkMinerReleaseSignature needs one signature line (base64 ASN.1 ECDSA)
// that a pinned key verifies, and a SHA256SUMS line naming the asset with
// the digest.
func checkMinerReleaseSignature(keys []*ecdsa.PublicKey, tag string, sums []byte, signature []byte, name string, digest string) error {
	hash := sha256.Sum256(minerReleaseSignedMessage(tag, sums))
	signed := false
	for _, line := range strings.Fields(string(signature)) {
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			continue
		}
		for _, key := range keys {
			if ecdsa.VerifyASN1(key, hash[:], raw) {
				signed = true
			}
		}
	}
	if !signed {
		return fmt.Errorf("the signature on release %s's %s isn't from a release key; nothing was changed", tag, minerReleaseSumsName)
	}
	scanner := bufio.NewScanner(bytes.NewReader(sums))
	for scanner.Scan() {
		// "<sha256>  <name>", or "<sha256> *<name>" for binary mode
		sum, file, ok := strings.Cut(scanner.Text(), " ")
		if !ok {
			continue
		}
		file = strings.TrimPrefix(strings.TrimPrefix(file, " "), "*")
		if file != name {
			continue
		}
		if !strings.EqualFold(sum, digest) {
			return fmt.Errorf("release %s's signed %s lists another digest for %s; nothing was changed", tag, minerReleaseSumsName, name)
		}
		return nil
	}
	return fmt.Errorf("release %s's signed %s doesn't list %s; nothing was changed", tag, minerReleaseSumsName, name)
}
