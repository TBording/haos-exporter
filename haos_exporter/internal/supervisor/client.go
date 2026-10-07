// Package supervisor is a GET-only client for the Home Assistant Supervisor
// API.
//
// The Supervisor authorises an app token by request path alone and never
// looks at the HTTP method, so the only protection against this process
// sending a write is that it cannot: Client has no method that sends any
// verb other than GET.
package supervisor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/TBording/haos-exporter/haos_exporter/internal/sanitize"
)

const (
	// DefaultTimeout bounds every request, including reading the body.
	DefaultTimeout = 5 * time.Second
	// MaxBodyBytes is the largest response body accepted. A larger body is
	// an error, never a truncated parse.
	MaxBodyBytes = 1 << 20

	maxMessageRunes = 200
)

// Paths the exporter reads.
const (
	PathHostInfo       = "/host/info"
	PathOSInfo         = "/os/info"
	PathCoreInfo       = "/core/info"
	PathSupervisorInfo = "/supervisor/info"
	PathResolutionInfo = "/resolution/info"
	PathBackupsInfo    = "/backups/info"
	PathSelfOptions    = "/addons/self/options/config"
	// PathAddons needs role manager. The self-check expects it to be
	// refused.
	PathAddons = "/addons"
)

var (
	// ErrForbidden is wrapped by the Error for a 403 response. The
	// Supervisor's security middleware answers 403 with a plain-text body,
	// before any handler runs.
	ErrForbidden = errors.New("403 forbidden")
	// ErrBodyTooLarge is wrapped by the Error for a body over MaxBodyBytes.
	ErrBodyTooLarge = fmt.Errorf("response body exceeds %d bytes", MaxBodyBytes)
)

// Error describes a failed request. It names the request path only: never
// the URL, a header or the token.
type Error struct {
	Path string
	// StatusCode is the HTTP status, or 0 when no response was received.
	StatusCode int
	msg        string
	err        error
}

func (e *Error) Error() string { return "GET " + e.Path + ": " + e.msg }

// Unwrap returns the cause, for errors.Is. It is never a *url.Error.
func (e *Error) Unwrap() error { return e.err }

// Client sends GET requests to the Supervisor with the app token.
type Client struct {
	base    string
	token   string
	timeout time.Duration
	http    *http.Client
}

// New returns a Client for baseURL (for example http://supervisor). The
// token is only ever placed in the Authorization header.
func New(baseURL, token string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, errors.New("supervisor URL does not parse")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("supervisor URL must be http(s)://host[:port][/path] with no credentials, query or fragment")
	}
	if token == "" {
		return nil, errors.New("supervisor token is empty")
	}
	transport := &http.Transport{
		// Never route the bearer token through an environment proxy.
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: DefaultTimeout}).DialContext,
		TLSHandshakeTimeout:   DefaultTimeout,
		ResponseHeaderTimeout: DefaultTimeout,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
	}
	return &Client{
		base:    strings.TrimRight(u.String(), "/"),
		token:   token,
		timeout: DefaultTimeout,
		http: &http.Client{
			Transport: transport,
			// A redirect is answered, never followed, so the token cannot
			// be carried to another path or host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

type envelope struct {
	Result  string          `json:"result"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// Get sends GET path and decodes the "data" member of the Supervisor's
// {"result","data"} envelope into out. A nil out discards the data.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	if !strings.HasPrefix(path, "/") {
		return &Error{Path: path, msg: "path must start with /", err: errors.New("invalid path")}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return &Error{Path: path, msg: "building request failed", err: errors.New("invalid request")}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return c.transportError(path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return &Error{Path: path, StatusCode: resp.StatusCode, msg: ErrForbidden.Error(), err: ErrForbidden}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return c.transportError(path, err)
	}
	if len(body) > MaxBodyBytes {
		return &Error{Path: path, StatusCode: resp.StatusCode, msg: ErrBodyTooLarge.Error(), err: ErrBodyTooLarge}
	}

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("unexpected status %d", resp.StatusCode)
		if m := c.bodyMessage(body); m != "" {
			msg += ": " + m
		}
		return &Error{Path: path, StatusCode: resp.StatusCode, msg: msg, err: errors.New("unexpected status")}
	}

	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return &Error{Path: path, StatusCode: resp.StatusCode, msg: "response is not a JSON envelope", err: err}
	}
	if env.Result != "ok" {
		msg := "result is not ok"
		if m := c.clean(env.Message); m != "" {
			msg += ": " + m
		}
		return &Error{Path: path, StatusCode: resp.StatusCode, msg: msg, err: errors.New("result not ok")}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return &Error{Path: path, StatusCode: resp.StatusCode, msg: "decoding data: " + c.clean(err.Error()), err: err}
	}
	return nil
}

// transportError drops the *url.Error wrapper, whose text carries the full
// URL, and describes the cause from a fixed vocabulary, so that the message
// never carries the dialled address either.
func (c *Client) transportError(path string, err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		err = uerr.Err
	}
	return &Error{Path: path, msg: transportMessage(err, c.timeout), err: err}
}

func transportMessage(err error, timeout time.Duration) string {
	var (
		dnsErr    *net.DNSError
		netErr    net.Error
		recordErr tls.RecordHeaderError
		certErr   *tls.CertificateVerificationError
	)
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &dnsErr):
		return "name resolution failed"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return fmt.Sprintf("timed out after %s", timeout)
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "connection closed by the server"
	case errors.As(err, &recordErr), errors.As(err, &certErr):
		return "TLS handshake failed"
	default:
		return "request failed"
	}
}

// bodyMessage extracts a short message from an error body: the envelope's
// "message" when the body is JSON, else the body text itself (the security
// middleware answers "403: Forbidden" or "404: Not Found" as plain text).
func (c *Client) bodyMessage(body []byte) string {
	var env envelope
	if json.Unmarshal(body, &env) == nil {
		return c.clean(env.Message)
	}
	return c.clean(string(body))
}

// clean makes text safe to log: printable, bounded, and without the token
// even if an upstream echoed it. The order matters. Sanitising first (with a
// limit of len(s), which never truncates) removes characters an upstream
// could interleave with the token to slip it past the redaction; truncating
// last means the cut can never leave a token prefix behind.
func (c *Client) clean(s string) string {
	s = sanitize.String(s, len(s))
	if c.token != "" {
		s = strings.ReplaceAll(s, c.token, "[redacted]")
	}
	return strings.TrimSpace(sanitize.String(s, maxMessageRunes))
}
