package miner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const signedTag = "v2026.10.21-1078274420"
const signedAsset = "urnetwork-provider-2026.10.21-1078274420.tar.gz"
const signedDigest = "684cb902f024eee6777d9afff68f0e106fea1defcc6a35cc7ba32fc4cbc0ea9e"

var signedSums = []byte("8211e29f461d4dc545bc5283c2c0d4ac7f0cce0da0d0022666f6dec986e2ff97  com.bringyour.network-2026.10.21-1078274420-play-release.aab\n" +
	signedDigest + "  " + signedAsset + "\n")

func newReleaseKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, base64.StdEncoding.EncodeToString(der)
}

func signRelease(t *testing.T, key *ecdsa.PrivateKey, tag string, sums []byte) []byte {
	t.Helper()
	hash := sha256.Sum256(minerReleaseSignedMessage(tag, sums))
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(signature) + "\n")
}

func TestMinerReleaseSignature(t *testing.T) {
	primary, primaryPublic := newReleaseKey(t)
	backup, backupPublic := newReleaseKey(t)
	other, _ := newReleaseKey(t)
	keys, err := parseMinerReleaseKeys([]string{primaryPublic, backupPublic})
	if err != nil {
		t.Fatal(err)
	}
	type check struct {
		signature []byte
		tag       string
		sums      []byte
		name      string
		digest    string
		ok        bool
	}
	edited := []byte(strings.Replace(string(signedSums), "8211", "0000", 1))
	checks := map[string]check{
		"primary key":            {signRelease(t, primary, signedTag, signedSums), signedTag, signedSums, signedAsset, signedDigest, true},
		"backup key":             {signRelease(t, backup, signedTag, signedSums), signedTag, signedSums, signedAsset, signedDigest, true},
		"two signatures":         {append(signRelease(t, other, signedTag, signedSums), signRelease(t, backup, signedTag, signedSums)...), signedTag, signedSums, signedAsset, signedDigest, true},
		"unpinned key":           {signRelease(t, other, signedTag, signedSums), signedTag, signedSums, signedAsset, signedDigest, false},
		"signed for another tag": {signRelease(t, primary, "v2026.10.20-1", signedSums), signedTag, signedSums, signedAsset, signedDigest, false},
		"edited sums":            {signRelease(t, primary, signedTag, signedSums), signedTag, edited, signedAsset, signedDigest, false},
		"other digest":           {signRelease(t, primary, signedTag, signedSums), signedTag, signedSums, signedAsset, strings.Repeat("0", 64), false},
		"not listed":             {signRelease(t, primary, signedTag, signedSums), signedTag, signedSums, "urnetwork-provider-evil.tar.gz", signedDigest, false},
		"empty signature":        {nil, signedTag, signedSums, signedAsset, signedDigest, false},
	}
	for name, c := range checks {
		t.Run(name, func(t *testing.T) {
			err := checkMinerReleaseSignature(keys, c.tag, c.sums, c.signature, c.name, c.digest)
			if c.ok && err != nil {
				t.Fatal(err)
			}
			if !c.ok && err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestMinerReleaseKeysMustBeP256(t *testing.T) {
	if _, err := parseMinerReleaseKeys([]string{"bm90IGEga2V5"}); err == nil {
		t.Fatal("accepted a key that isn't one")
	}
}

// The release's two files are read from the release, and a release without
// them is refused once a key is pinned. Nothing is checked while none is.
func TestMinerReleaseSignatureFiles(t *testing.T) {
	t.Setenv("URNETWORK_UPDATE_URL", "test")
	dir := t.TempDir()
	primary, primaryPublic := newReleaseKey(t)
	os.WriteFile(filepath.Join(dir, minerReleaseSumsName), signedSums, 0600)
	os.WriteFile(filepath.Join(dir, minerReleaseSignatureName), signRelease(t, primary, signedTag, signedSums), 0600)
	asset := minerReleaseAsset{Name: signedAsset, Digest: "sha256:" + signedDigest, Url: signedAsset}
	release := &minerRelease{TagName: signedTag, base: dir, Assets: []minerReleaseAsset{
		asset,
		{Name: minerReleaseSumsName, Url: minerReleaseSumsName},
		{Name: minerReleaseSignatureName, Url: minerReleaseSignatureName},
	}}
	unsigned := &minerRelease{TagName: signedTag, base: dir, Assets: []minerReleaseAsset{asset}}

	keys := minerReleaseKeys
	defer func() { minerReleaseKeys = keys }()
	minerReleaseKeys = nil
	if err := verifyMinerReleaseSignature(t.Context(), unsigned, &asset, signedDigest); err != nil {
		t.Fatalf("checked a signature with no key pinned: %v", err)
	}
	minerReleaseKeys = []string{primaryPublic}
	if err := verifyMinerReleaseSignature(t.Context(), release, &asset, signedDigest); err != nil {
		t.Fatal(err)
	}
	if err := verifyMinerReleaseSignature(t.Context(), unsigned, &asset, signedDigest); err == nil || !strings.Contains(err.Error(), "isn't signed") {
		t.Fatalf("accepted an unsigned release: %v", err)
	}
}

// What the release machine runs: openssl (or the Secure Enclave helper)
// signs the same message and the miner accepts it.
func TestMinerReleaseSignatureFromOpenssl(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("no openssl")
	}
	dir := t.TempDir()
	key, public := newReleaseKey(t)
	der, _ := x509.MarshalECPrivateKey(key)
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600)
	messagePath := filepath.Join(dir, "message")
	os.WriteFile(messagePath, minerReleaseSignedMessage(signedTag, signedSums), 0600)
	out, err := exec.Command("openssl", "dgst", "-sha256", "-sign", keyPath, messagePath).Output()
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := parseMinerReleaseKeys([]string{public})
	signature := []byte(base64.StdEncoding.EncodeToString(out) + "\n")
	if err := checkMinerReleaseSignature(keys, signedTag, signedSums, signature, signedAsset, signedDigest); err != nil {
		t.Fatal(err)
	}
}
