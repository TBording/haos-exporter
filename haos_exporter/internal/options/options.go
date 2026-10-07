// Package options loads and validates the app options.
//
// Inside Home Assistant the options come from GET
// /addons/self/options/config, because /data/options.json is root-owned
// 0600 and unreadable by the exporter's non-root user.
package options

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"github.com/TBording/haos-exporter/haos_exporter/internal/supervisor"
)

// TLS modes.
const (
	TLSSelfSigned = "self_signed"
	TLSProvided   = "provided"
	TLSOff        = "off"
)

// Defaults applied to empty options.
const (
	DefaultUsername = "prometheus"
	DefaultTLSMode  = TLSSelfSigned
	DefaultLogLevel = "info"
)

const maxFileBytes = 1 << 20

// ErrNoPasswordHash means basic_auth_password_hash is empty. The exporter
// refuses to serve without basic auth.
var ErrNoPasswordHash = errors.New("basic_auth_password_hash is not set")

// Options are the app options. Unknown keys are ignored.
type Options struct {
	BasicAuthUsername     string `json:"basic_auth_username"`
	BasicAuthPasswordHash string `json:"basic_auth_password_hash"`
	TLSMode               string `json:"tls_mode"`
	TLSClientAuth         bool   `json:"tls_client_auth"`
	LogLevel              string `json:"log_level"`
}

// String never includes the password hash.
func (o Options) String() string {
	return fmt.Sprintf("basic_auth_username=%q basic_auth_password_hash_set=%t tls_mode=%q tls_client_auth=%t log_level=%q",
		o.BasicAuthUsername, o.BasicAuthPasswordHash != "", o.TLSMode, o.TLSClientAuth, o.LogLevel)
}

// LogValue never includes the password hash.
func (o Options) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("basic_auth_username", o.BasicAuthUsername),
		slog.Bool("basic_auth_password_hash_set", o.BasicAuthPasswordHash != ""),
		slog.String("tls_mode", o.TLSMode),
		slog.Bool("tls_client_auth", o.TLSClientAuth),
		slog.String("log_level", o.LogLevel),
	)
}

// Getter is the read side of the Supervisor client.
type Getter interface {
	Get(ctx context.Context, path string, out any) error
}

// FromSupervisor reads the options from GET /addons/self/options/config and
// validates them.
func FromSupervisor(ctx context.Context, g Getter) (Options, error) {
	var o Options
	if err := g.Get(ctx, supervisor.PathSelfOptions, &o); err != nil {
		return Options{}, fmt.Errorf("reading app options: %w", err)
	}
	return o, o.normalize()
}

// FromFile reads the options from a JSON object in path (the shape of
// /data/options.json) and validates them. It is for running outside Home
// Assistant.
func FromFile(path string) (Options, error) {
	f, err := os.Open(path)
	if err != nil {
		return Options{}, fmt.Errorf("reading options file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return Options{}, fmt.Errorf("reading options file: %w", err)
	}
	if len(data) > maxFileBytes {
		return Options{}, fmt.Errorf("options file exceeds %d bytes", maxFileBytes)
	}
	var o Options
	if err := json.Unmarshal(data, &o); err != nil {
		return Options{}, fmt.Errorf("options file is not a JSON object: %w", err)
	}
	return o, o.normalize()
}

// normalize applies defaults and validates. Error messages never include
// the hash.
func (o *Options) normalize() error {
	if o.BasicAuthUsername == "" {
		o.BasicAuthUsername = DefaultUsername
	}
	if o.TLSMode == "" {
		o.TLSMode = DefaultTLSMode
	}
	if o.LogLevel == "" {
		o.LogLevel = DefaultLogLevel
	}
	if !validUsername(o.BasicAuthUsername) {
		return errors.New("basic_auth_username must be printable and must not contain ':'")
	}
	if o.BasicAuthPasswordHash == "" {
		return ErrNoPasswordHash
	}
	if !ValidBcryptHash(o.BasicAuthPasswordHash) {
		return errors.New("basic_auth_password_hash is not a bcrypt hash ($2a$, $2b$ or $2y$, 60 characters)")
	}
	switch o.TLSMode {
	case TLSSelfSigned, TLSProvided, TLSOff:
	default:
		return fmt.Errorf("tls_mode must be %q, %q or %q", TLSSelfSigned, TLSProvided, TLSOff)
	}
	if o.TLSClientAuth && o.TLSMode == TLSOff {
		return errors.New("tls_client_auth needs TLS, but tls_mode is off")
	}
	if _, err := ParseLogLevel(o.LogLevel); err != nil {
		return err
	}
	return nil
}

func validUsername(u string) bool {
	if strings.ContainsRune(u, ':') {
		return false
	}
	for _, r := range u {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// ValidBcryptHash reports whether h is a well-formed bcrypt hash with a
// $2a$, $2b$ or $2y$ prefix.
func ValidBcryptHash(h string) bool {
	if len(h) != 60 {
		return false
	}
	if !strings.HasPrefix(h, "$2a$") && !strings.HasPrefix(h, "$2b$") && !strings.HasPrefix(h, "$2y$") {
		return false
	}
	if _, err := bcrypt.Cost([]byte(h)); err != nil {
		return false
	}
	// $2x$NN$ then 53 characters of bcrypt's base64 alphabet.
	if h[6] != '$' {
		return false
	}
	for _, r := range h[7:] {
		if !strings.ContainsRune("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", r) {
			return false
		}
	}
	return true
}

// ParseLogLevel maps debug, info, warn or error onto a slog.Level.
func ParseLogLevel(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, errors.New(`log_level must be "debug", "info", "warn" or "error"`)
	}
}
