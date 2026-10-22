package miner

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Every immutable release of urnetwork/build carries a release attestation
// that GitHub signs when the release is published: an in-toto statement
// naming the repository, the tag and the sha256 of every asset. An update
// installs a download only when such a statement, signed by GitHub's
// release signer and bound to urnetwork/build and the release's tag, lists
// the download's name and digest.
//
// This checks what GitHub recorded at publication, independently of the
// release JSON and the download host. It does not say who published the
// release: anyone who can publish a urnetwork/build release gets a valid
// attestation for it.

// The repository is pinned by name and by id, so a renamed or recreated
// repository with the same name doesn't pass.
const minerReleaseRepository = "urnetwork/build"
var minerReleaseRepositoryId = "936244679"

const minerReleaseAttestationSource = "https://api.github.com/repos/" + minerReleaseRepository + "/attestations/sha256:"

// GitHub's release signer. The certificate carries no OIDC issuer.
const minerReleaseSigner = "https://dotcom.releases.github.com"

var minerReleasePredicateTypes = map[string]bool{
	"https://in-toto.io/attestation/release/v0.1": true,
	"https://in-toto.io/attestation/release/v0.2": true,
}

// GitHub's Sigstore TUF repository, whose root of trust ships in this
// binary. trusted_root.json (the signing and timestamp CAs) is refreshed
// from it and cached beside the miner's state; the copy that ships in this
// binary is used when the repository can't be reached.
const minerReleaseTufRepository = "https://tuf-repo.github.com"

//go:embed release/github-tuf-root.json
var minerReleaseTufRoot []byte

//go:embed release/github-trusted-root.json
var minerReleaseTrustedRoot []byte

// minerReleaseTrust is replaced in tests.
var minerReleaseTrust = loadMinerReleaseTrust

func loadMinerReleaseTrust() (root.TrustedMaterial, error) {
	if raw, err := fetchMinerReleaseTrustedRoot(); err == nil {
		if trusted, err := root.NewTrustedRootFromJSON(raw); err == nil {
			return trusted, nil
		}
	}
	return root.NewTrustedRootFromJSON(minerReleaseTrustedRoot)
}

func fetchMinerReleaseTrustedRoot() ([]byte, error) {
	opts := tuf.DefaultOptions()
	opts.Root = minerReleaseTufRoot
	opts.RepositoryBaseURL = minerReleaseTufRepository
	opts.DisableLocalCache = true
	if path, err := providerStatePath("tuf"); err == nil {
		if err := os.MkdirAll(path, 0700); err == nil {
			opts.CachePath = path
			opts.DisableLocalCache = false
		}
	}
	client, err := tuf.New(opts)
	if err != nil {
		return nil, err
	}
	return client.GetTarget("trusted_root.json")
}

type minerAttestations struct {
	Attestations []struct {
		Bundle json.RawMessage `json:"bundle"`
	} `json:"attestations"`
}

type minerReleasePredicate struct {
	Repository   string `json:"repository"`
	RepositoryId string `json:"repositoryId"`
	Tag          string `json:"tag"`
}

// fetchMinerReleaseAttestations lists the attestations GitHub has for a
// sha256 digest in urnetwork/build.
func fetchMinerReleaseAttestations(ctx context.Context, digest string) (*minerAttestations, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	body, err := minerOpen(ctx, minerReleaseAttestationSource+digest, "")
	if err != nil {
		return nil, err
	}
	defer body.Close()
	attestations := &minerAttestations{}
	if err := json.NewDecoder(io.LimitReader(body, 8<<20)).Decode(attestations); err != nil {
		return nil, fmt.Errorf("the attestation list isn't readable: %w", err)
	}
	return attestations, nil
}

// verifyMinerReleaseAttestation checks that GitHub attested the asset, by
// name and digest, as part of this release of urnetwork/build.
func verifyMinerReleaseAttestation(ctx context.Context, release *minerRelease, asset *minerReleaseAsset, digest string) error {
	attestations, err := fetchMinerReleaseAttestations(ctx, digest)
	if err != nil {
		return fmt.Errorf("couldn't get the release attestation for %s: %w", asset.Name, err)
	}
	return checkMinerReleaseAttestations(attestations, release, asset, digest)
}

func checkMinerReleaseAttestations(attestations *minerAttestations, release *minerRelease, asset *minerReleaseAsset, digest string) error {
	if len(attestations.Attestations) == 0 {
		return fmt.Errorf("release %s has no attestation for %s; it may not be an immutable release", release.TagName, asset.Name)
	}
	trusted, err := minerReleaseTrust()
	if err != nil {
		return fmt.Errorf("can't load GitHub's signing roots: %w", err)
	}
	verifier, err := verify.NewVerifier(trusted, verify.WithSignedTimestamps(1))
	if err != nil {
		return err
	}
	want, err := hex.DecodeString(digest)
	if err != nil {
		return err
	}
	signer, err := verify.NewSANMatcher(minerReleaseSigner, "")
	if err != nil {
		return err
	}
	issuer, err := verify.NewIssuerMatcher("", ".*")
	if err != nil {
		return err
	}
	identity, err := verify.NewCertificateIdentity(signer, issuer, certificate.Extensions{})
	if err != nil {
		return err
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest("sha256", want), verify.WithCertificateIdentity(identity))
	var problems []error
	for _, attestation := range attestations.Attestations {
		b := &bundle.Bundle{}
		if err := b.UnmarshalJSON(attestation.Bundle); err != nil {
			problems = append(problems, err)
			continue
		}
		result, err := verifier.Verify(b, policy)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		statement := result.Statement
		if statement == nil || !minerReleasePredicateTypes[statement.GetPredicateType()] {
			problems = append(problems, errors.New("not a release attestation"))
			continue
		}
		raw, err := statement.GetPredicate().MarshalJSON()
		if err != nil {
			problems = append(problems, err)
			continue
		}
		predicate := minerReleasePredicate{}
		if err := json.Unmarshal(raw, &predicate); err != nil {
			problems = append(problems, err)
			continue
		}
		if predicate.Repository != minerReleaseRepository || predicate.RepositoryId != minerReleaseRepositoryId {
			problems = append(problems, fmt.Errorf("attested for %s (%s), not %s", predicate.Repository, predicate.RepositoryId, minerReleaseRepository))
			continue
		}
		if predicate.Tag != release.TagName {
			problems = append(problems, fmt.Errorf("attested for release %s, not %s", predicate.Tag, release.TagName))
			continue
		}
		// the digest matched some subject; it must be this asset's
		named := false
		for _, subject := range statement.GetSubject() {
			if subject.GetName() == asset.Name && strings.EqualFold(subject.GetDigest()["sha256"], digest) {
				named = true
			}
		}
		if !named {
			problems = append(problems, fmt.Errorf("the attestation doesn't list %s with this digest", asset.Name))
			continue
		}
		return nil
	}
	return fmt.Errorf("release %s has no valid GitHub attestation for %s: %w", release.TagName, asset.Name, errors.Join(problems...))
}
