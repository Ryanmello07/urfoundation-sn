package miner

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// A real release attestation of urnetwork/build, checked against the
// trusted root that ships in the binary (no network).
const attestedTag = "v2026.10.21-1078274420"
const attestedAsset = "urnetwork-provider-2026.10.21-1078274420.tar.gz"
const attestedDigest = "684cb902f024eee6777d9afff68f0e106fea1defcc6a35cc7ba32fc4cbc0ea9e"

func readAttestedRelease(t *testing.T) *minerAttestations {
	t.Helper()
	trust := minerReleaseTrust
	minerReleaseTrust = func() (root.TrustedMaterial, error) {
		return root.NewTrustedRootFromJSON(minerReleaseTrustedRoot)
	}
	t.Cleanup(func() { minerReleaseTrust = trust })
	raw, err := os.ReadFile("testdata/release/attestations-" + attestedTag + ".json")
	if err != nil {
		t.Fatal(err)
	}
	attestations := &minerAttestations{}
	if err := json.Unmarshal(raw, attestations); err != nil {
		t.Fatal(err)
	}
	return attestations
}

func attestedRelease(tag string, name string) (*minerRelease, *minerReleaseAsset) {
	release := &minerRelease{TagName: tag}
	return release, &minerReleaseAsset{Name: name, Digest: "sha256:" + attestedDigest}
}

func TestMinerReleaseAttestationAccepts(t *testing.T) {
	attestations := readAttestedRelease(t)
	release, asset := attestedRelease(attestedTag, attestedAsset)
	if err := checkMinerReleaseAttestations(attestations, release, asset, attestedDigest); err != nil {
		t.Fatal(err)
	}
}

func TestMinerReleaseAttestationRefuses(t *testing.T) {
	cases := map[string]func(*minerAttestations) (*minerRelease, *minerReleaseAsset, string){
		"other digest": func(*minerAttestations) (*minerRelease, *minerReleaseAsset, string) {
			release, asset := attestedRelease(attestedTag, attestedAsset)
			return release, asset, strings.Repeat("0", 64)
		},
		"another asset's name": func(*minerAttestations) (*minerRelease, *minerReleaseAsset, string) {
			release, asset := attestedRelease(attestedTag, "urnetwork-provider-2026.10.21-1078274420-linux-amd64.tar.gz")
			return release, asset, attestedDigest
		},
		"other tag": func(*minerAttestations) (*minerRelease, *minerReleaseAsset, string) {
			release, asset := attestedRelease("v2026.10.22-1", attestedAsset)
			return release, asset, attestedDigest
		},
		"no attestation": func(attestations *minerAttestations) (*minerRelease, *minerReleaseAsset, string) {
			attestations.Attestations = nil
			release, asset := attestedRelease(attestedTag, attestedAsset)
			return release, asset, attestedDigest
		},
		"edited statement": func(attestations *minerAttestations) (*minerRelease, *minerReleaseAsset, string) {
			b := map[string]any{}
			_ = json.Unmarshal(attestations.Attestations[0].Bundle, &b)
			envelope := b["dsseEnvelope"].(map[string]any)
			payload, _ := base64.StdEncoding.DecodeString(envelope["payload"].(string))
			payload = []byte(strings.Replace(string(payload), attestedAsset, "urnetwork-provider-evil.tar.gz", 1))
			envelope["payload"] = base64.StdEncoding.EncodeToString(payload)
			attestations.Attestations[0].Bundle, _ = json.Marshal(b)
			release, asset := attestedRelease(attestedTag, "urnetwork-provider-evil.tar.gz")
			return release, asset, attestedDigest
		},
		"no signed timestamp": func(attestations *minerAttestations) (*minerRelease, *minerReleaseAsset, string) {
			b := map[string]any{}
			_ = json.Unmarshal(attestations.Attestations[0].Bundle, &b)
			delete(b["verificationMaterial"].(map[string]any), "timestampVerificationData")
			attestations.Attestations[0].Bundle, _ = json.Marshal(b)
			release, asset := attestedRelease(attestedTag, attestedAsset)
			return release, asset, attestedDigest
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			attestations := readAttestedRelease(t)
			release, asset, digest := change(attestations)
			if err := checkMinerReleaseAttestations(attestations, release, asset, digest); err == nil {
				t.Fatal("accepted")
			} else {
				t.Log(err)
			}
		})
	}
}

// The repository and signer are pinned: a release attestation of any other
// repository, which GitHub signs with the same identity, doesn't pass.
func TestMinerReleaseAttestationPinsRepository(t *testing.T) {
	attestations := readAttestedRelease(t)
	release, asset := attestedRelease(attestedTag, attestedAsset)
	repository := minerReleaseRepositoryId
	defer func() { minerReleaseRepositoryId = repository }()
	minerReleaseRepositoryId = "1"
	if err := checkMinerReleaseAttestations(attestations, release, asset, attestedDigest); err == nil || !strings.Contains(err.Error(), "not urnetwork/build") {
		t.Fatalf("accepted another repository: %v", err)
	}
}
