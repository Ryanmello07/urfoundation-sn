// A diagnostic for proxy providers whose sign-in keeps retrying. The closed
// diagnostics schema reports such a wait as cause "unknown"; this names the
// error types and HTTP status behind it, and nothing else: no message text,
// address, token or response body is printed.
package miner

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/urnetwork/connect"
)

// ProviderRetryCauseEnv turns on one stderr line per sign-in retry.
const ProviderRetryCauseEnv = "URNETWORK_PROVIDER_RETRY_CAUSE"

func providerRetryCauseEnabled() bool {
	return os.Getenv(ProviderRetryCauseEnv) == "1"
}

// providerRetryCauseSummary walks the error tree, at most 64 nodes, and
// returns its shape, such as "*sdk.NetworkClientRegistrationUnavailableError>
// *connect.HttpStatusError{status=429}".
func providerRetryCauseSummary(err error) string {
	budget := 64
	var walk func(error) string
	walk = func(err error) string {
		if err == nil {
			return "nil"
		}
		budget--
		if budget < 0 {
			return "..."
		}
		node := fmt.Sprintf("%T", err)
		var detail []string
		switch leaf := err.(type) {
		case *connect.HttpStatusError:
			detail = append(detail, fmt.Sprintf("status=%d", leaf.StatusCode))
		case *net.OpError:
			detail = append(detail, "op="+leaf.Op)
		case syscall.Errno:
			detail = append(detail, "errno="+leaf.Error())
		}
		if errors.Is(err, os.ErrDeadlineExceeded) && len(detail) == 0 {
			detail = append(detail, "deadline")
		}
		if network, ok := err.(net.Error); ok && network.Timeout() {
			detail = append(detail, "timeout")
		}
		if len(detail) > 0 {
			node += "{" + strings.Join(detail, ",") + "}"
		}
		switch wrapped := err.(type) {
		case interface{ Unwrap() []error }:
			causes := wrapped.Unwrap()
			parts := make([]string, 0, len(causes))
			for _, cause := range causes {
				parts = append(parts, walk(cause))
			}
			return node + ">[" + strings.Join(parts, "|") + "]"
		case interface{ Unwrap() error }:
			if cause := wrapped.Unwrap(); cause != nil {
				return node + ">" + walk(cause)
			}
		}
		return node
	}
	return walk(err)
}

func logProviderRetryCause(index uint64, retries int, elapsed time.Duration, delay time.Duration, err error) {
	fmt.Fprintf(os.Stderr, "provider_retry_cause provider=%d retry=%d attempt_ms=%d wait_ms=%d cause=%s\n", index, retries, elapsed.Milliseconds(), delay.Milliseconds(), providerRetryCauseSummary(err))
}
