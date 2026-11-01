package miner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// a refusal as connect reports it from a socks dial
func proxyRefusalForTest(t *testing.T) error {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 64)
		conn.Read(buffer)
		// no acceptable methods
		conn.Write([]byte{5, 0xff})
	}()
	settings := &connect.ProxySettings{Network: "tcp", Address: listener.Addr().String()}
	dial := settings.NewDialContext(context.Background(), &net.Dialer{Timeout: 5 * time.Second})
	_, err = dial(context.Background(), "tcp", "example.com:443")
	var refusal *connect.ProxyUnavailableError
	if !errors.As(err, &refusal) {
		t.Fatalf("dial error %v is not a proxy refusal", err)
	}
	return err
}

func TestProxyRefusalNoticeShowsOncePerInterval(t *testing.T) {
	refusal := proxyRefusalForTest(t)
	nested := errors.Join(fmt.Errorf("attempt: %w", refusal), context.DeadlineExceeded)
	clock := time.Unix(1000, 0)
	var out bytes.Buffer
	notice := newProxyRefusalNotice(&out, 30)
	notice.now = func() time.Time { return clock }
	if notice.show(context.DeadlineExceeded) {
		t.Fatal("notice shown for a plain timeout")
	}
	if !notice.show(nested) {
		t.Fatal("notice not shown for a nested refusal")
	}
	if !strings.Contains(out.String(), "30 proxies configured") || !strings.Contains(out.String(), "fewer proxies per account") {
		t.Fatalf("notice text %q", out.String())
	}
	if notice.show(nested) {
		t.Fatal("notice repeated within its interval")
	}
	clock = clock.Add(proxyRefusalNoticeInterval)
	if !notice.show(nested) {
		t.Fatal("notice not repeated after its interval")
	}
}

// A direct run carries no notice, so its sign-in retries print nothing; a
// proxy run's notice is the one its context carries.
func TestProxyRefusalNoticeOnlyInProxyRuns(t *testing.T) {
	refusal := proxyRefusalForTest(t)
	direct := context.Background()
	if notice := proxyRefusalNoticeFrom(direct); notice != nil || notice.show(refusal) {
		t.Fatal("a direct run has a proxy refusal notice")
	}
	var out bytes.Buffer
	notice := newProxyRefusalNotice(&out, 2)
	proxied := context.WithValue(direct, proxyRefusalNoticeKey{}, notice)
	if proxyRefusalNoticeFrom(proxied) != notice || !proxyRefusalNoticeFrom(proxied).show(refusal) {
		t.Fatal("a proxy run's notice did not show")
	}
}
