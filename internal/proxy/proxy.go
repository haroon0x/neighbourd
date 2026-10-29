// Package proxy forwards a signed request from a paired peer to a local service.
//
// The local service stays bound to loopback. This handler is the only thing that
// talks to it, and it is reached only through the authenticated routing, so the
// caller has already proven it holds a pinned key and a valid token.
//
// Two rules matter more than the forwarding itself:
//
//   - the dialer refuses any address that is not loopback, checked after
//     resolution, so a hostname that resolves off-box cannot be used to pivot.
//   - caller-supplied credentials are not forwarded. A peer must not be able to
//     smuggle an Authorization header into a local service that trusts them.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MaxBody caps a forwarded request body. Local APIs take JSON, not uploads.
const MaxBody = 8 << 20

// Handler proxies to one target.
type Handler struct {
	Origin string
	Client *http.Client

	// AllowRemote disables the loopback-only dial guard. Only ever set from an
	// explicit operator flag.
	AllowRemote bool
}

// hopHeaders are connection-scoped and must not be copied either way.
var hopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// forwardedRequest lists what a caller may send. Everything else is dropped,
// including Authorization, Cookie and this protocol's own headers: they were
// consumed by authentication and have no meaning to a local service.
var forwardedRequest = map[string]bool{
	"content-type":  true,
	"accept":        true,
	"cache-control": true,
	"user-agent":    true,
}

func (h *Handler) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		// No overall timeout: a model can take minutes to answer, and killing it
		// mid-stream is worse than waiting. Header and idle timeouts still apply.
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, err
				}
				for _, ip := range ips {
					if !h.AllowRemote && !ip.IP.IsLoopback() {
						return nil, fmt.Errorf("refused: %s resolves to %s, which is not loopback", host, ip.IP)
					}
				}
				addr = net.JoinHostPort(ips[0].IP.String(), port)
				return dialer.DialContext(ctx, network, addr)
			},
			ResponseHeaderTimeout: 5 * time.Minute,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          8,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // a redirect is the caller's business
		},
	}
}

// Serve forwards r to origin+rest and streams the answer back.
//
// rest is the path after the resource name, already validated by the caller not
// to escape the origin.
func (h *Handler) Serve(w http.ResponseWriter, r *http.Request, rest string) {
	if rest == "" {
		rest = "/"
	}
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}

	target, err := url.Parse(h.Origin + rest)
	if err != nil {
		http.Error(w, "bad forwarded path", http.StatusBadRequest)
		return
	}
	target.RawQuery = r.URL.RawQuery

	body := http.MaxBytesReader(w, r.Body, MaxBody)
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
	if err != nil {
		http.Error(w, "could not build the forwarded request", http.StatusBadGateway)
		return
	}
	out.ContentLength = r.ContentLength
	for k, v := range r.Header {
		if forwardedRequest[strings.ToLower(k)] {
			out.Header[k] = v
		}
	}

	resp, err := h.client().Do(out)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, fmt.Sprintf("request body over %d bytes", MaxBody), http.StatusRequestEntityTooLarge)
			return
		}
		// The local service is down or refused; say so without leaking its internals.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "local service did not answer: %v\n", err)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		if !hopHeaders[strings.ToLower(k)] {
			w.Header()[k] = v
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy with an explicit flush per chunk: local APIs that stream (token by
	// token, or newline-delimited JSON) must not be buffered into one blob.
	rc := http.NewResponseController(w)
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			rc.Flush()
		}
		if err != nil {
			if err != io.EOF {
				// Mid-stream failure: nothing left to say on this response.
				return
			}
			return
		}
	}
}
