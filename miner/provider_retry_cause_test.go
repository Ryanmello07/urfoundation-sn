package miner

import (
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/connect"
)

func TestProviderRetryCauseSummaryNamesTypesAndStatusOnly(t *testing.T) {
	secret := "eyJsecret-token-text"
	status := &connect.HttpStatusError{StatusCode: 429, Status: "429 Too Many Requests", Body: []byte(secret)}
	err := errors.Join(errors.New(secret), status)
	got := providerRetryCauseSummary(err)
	if !strings.Contains(got, "*connect.HttpStatusError{status=429}") {
		t.Fatalf("summary %q lacks the status", got)
	}
	if strings.Contains(got, secret) || strings.Contains(got, "Too Many") {
		t.Fatalf("summary %q leaks message text", got)
	}
	if got := providerRetryCauseSummary(nil); got != "nil" {
		t.Fatalf("nil summary %q", got)
	}
}
