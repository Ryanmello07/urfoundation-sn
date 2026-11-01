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
	notice := &proxyRefusalNotice{now: func() time.Time { return clock }}
	var out bytes.Buffer
	if notice.show(&out, context.DeadlineExceeded, 30) {
		t.Fatal("notice shown for a plain timeout")
	}
	if !notice.show(&out, nested, 30) {
		t.Fatal("notice not shown for a nested refusal")
	}
	if !strings.Contains(out.String(), "30 proxies configured") || !strings.Contains(out.String(), "fewer proxies per account") {
		t.Fatalf("notice text %q", out.String())
	}
	if notice.show(&out, nested, 30) {
		t.Fatal("notice repeated within its interval")
	}
	clock = clock.Add(proxyRefusalNoticeInterval)
	if !notice.show(&out, nested, 30) {
		t.Fatal("notice not repeated after its interval")
	}
}
