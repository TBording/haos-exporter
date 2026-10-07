// Package sanitize makes externally supplied strings safe to use as
// Prometheus label values and in log lines.
package sanitize

import (
	"strings"
	"unicode"
)

// MaxLabelRunes is the longest label value the exporter emits.
const MaxLabelRunes = 128

// Label returns s as valid UTF-8 with non-printable characters removed,
// truncated to MaxLabelRunes runes.
func Label(s string) string {
	return String(s, MaxLabelRunes)
}

// String returns s as valid UTF-8 with non-printable characters removed,
// truncated to limit runes.
func String(s string, limit int) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == limit {
			break
		}
		if !unicode.IsPrint(r) {
			continue
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
