package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLabel(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Terminal & SSH", "Terminal & SSH"},
		{"empty", "", ""},
		{"invalid utf8 dropped", "ab\xffcd", "abcd"},
		{"control chars dropped", "a\x00b\x07c\nd\te", "abcde"},
		{"multibyte kept", "Tür → Café", "Tür → Café"},
		{"literal replacement char kept", "a�b", "a�b"},
		{"truncated to 128 runes", strings.Repeat("é", 200), strings.Repeat("é", 128)},
		{"truncation counts printable runes only", strings.Repeat("\x01a", 200), strings.Repeat("a", 128)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Label(tt.in)
			if got != tt.want {
				t.Fatalf("Label(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("Label(%q) returned invalid UTF-8", tt.in)
			}
		})
	}
}
