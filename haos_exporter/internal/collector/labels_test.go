package collector

import (
	"strings"
	"testing"
)

func TestValidSlug(t *testing.T) {
	tests := []struct {
		slug string
		ok   bool
	}{
		{"core_ssh", true},
		{"0123abcd_editor", true},
		{"local_my-app.v2", true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
		{"", false},
		{"bad slug", false},
		{"a/b", false},
		{"../x", false},
		{"ünicode", false},
		{"slug\n", false},
	}
	for _, tt := range tests {
		if got := validSlug(tt.slug); got != tt.ok {
			t.Errorf("validSlug(%q) = %t, want %t", tt.slug, got, tt.ok)
		}
	}
}

func TestAppState(t *testing.T) {
	for in, want := range map[string]string{
		"started": "started", "stopped": "stopped", "startup": "startup", "error": "error",
		"unknown": "unknown", "rebuilding": "unknown", "": "unknown", "Started": "unknown",
	} {
		if got := appState(in); got != want {
			t.Errorf("appState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBackupType(t *testing.T) {
	for in, want := range map[string]string{
		"full": "full", "partial": "partial", "": "other", "Full": "other", "legacy": "other",
	} {
		if got := backupType(in); got != want {
			t.Errorf("backupType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseBackupDate(t *testing.T) {
	tests := []struct {
		in   string
		want float64
		ok   bool
	}{
		{"2026-09-28T02:59:51.123456+00:00", 1790564391.123456, true},
		{"2026-09-28T02:59:51+00:00", 1790564391, true},
		{"2026-09-28T04:59:51.5+02:00", 1790564391.5, true},
		{"2026-09-28T02:59:51Z", 1790564391, true},
		{"2026-09-28T02:59:51.123456", 0, false},
		{"2026-09-28 02:59:51+00:00", 0, false},
		{"", 0, false},
	}
	for _, tt := range tests {
		d, err := parseBackupDate(tt.in)
		if (err == nil) != tt.ok {
			t.Errorf("parseBackupDate(%q) error = %v, want ok=%t", tt.in, err, tt.ok)
			continue
		}
		if tt.ok && unixSeconds(d) != tt.want {
			t.Errorf("parseBackupDate(%q) = %v, want %v", tt.in, unixSeconds(d), tt.want)
		}
	}
}
