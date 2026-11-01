// A notice for proxy providers whose proxy keeps refusing them. Many proxy
// plans cap how many connections one account holds open at once; past the
// cap the gateway refuses new connections, often as "no acceptable
// authentication methods", although the login itself is right. One account
// tested this way allowed 32 open connections, and each provider holds about
// one, so only about 30 of its proxies could ever sign in.
package miner

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/urnetwork/connect"
)

// proxyRefusalNoticeInterval spaces out the notice; it repeats while the
// refusals continue, so a long log still shows why providers are waiting.
const proxyRefusalNoticeInterval = 10 * time.Minute

type proxyRefusalNotice struct {
	mutex sync.Mutex
	last  time.Time
	now   func() time.Time
}

var providerProxyRefusalNotice = &proxyRefusalNotice{now: time.Now}

// providerProxyCountKey carries the number of configured proxies of one
// provider run, present only when the run uses proxies.
type providerProxyCountKey struct{}

// show prints the notice when err holds a proxy refusal and the last notice
// is older than the interval. It reports whether it printed.
func (self *proxyRefusalNotice) show(out io.Writer, err error, proxyCount int) bool {
	if out == nil || !proxyRefused(err, 0) {
		return false
	}
	self.mutex.Lock()
	now := self.now()
	if !self.last.IsZero() && now.Sub(self.last) < proxyRefusalNoticeInterval {
		self.mutex.Unlock()
		return false
	}
	self.last = now
	self.mutex.Unlock()
	fmt.Fprintf(out, "Some proxy providers are waiting: the proxy refused new connections (%d proxies configured).\n"+
		"Many proxy plans limit how many connections one account can keep open at once, and refuse the rest, sometimes as \"no acceptable authentication methods\" even when the login is right. Each provider keeps about one connection open.\n"+
		"If only some providers sign in, configure fewer proxies per account, or spread them over more accounts. The waiting providers keep retrying.\n", proxyCount)
	return true
}

// proxyRefused walks the error tree, at most 32 levels deep, for a socks
// refusal from the proxy.
func proxyRefused(err error, depth int) bool {
	if err == nil || 32 < depth {
		return false
	}
	if _, ok := err.(*connect.ProxyUnavailableError); ok {
		return true
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		for _, cause := range wrapped.Unwrap() {
			if proxyRefused(cause, depth+1) {
				return true
			}
		}
	case interface{ Unwrap() error }:
		return proxyRefused(wrapped.Unwrap(), depth+1)
	}
	return false
}
