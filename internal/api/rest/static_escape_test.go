package rest

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The control center builds HTML from event/alert/trace fields that other
// modules supply, so every such interpolation must go through escHtml.
// This guards against regressions of the stored-XSS fix.
func TestIndexHTMLEscapesDynamicFields(t *testing.T) {
	b, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)

	// Inline handlers must not embed data in a JS string; HTML-escaping does not
	// protect there because the browser decodes entities before running the JS.
	if m := regexp.MustCompile(`on\w+="[^"]*\('\$\{`).FindString(src); m != "" {
		t.Errorf("data interpolated into inline handler JS string: %s", m)
	}

	// Plain field reads such as ${ev.module} or ${t.name || '—'} must be wrapped.
	field := regexp.MustCompile(`\$\{\s*([a-z]\w*(?:\??\.\w+)+)\s*(?:(?:\|\||\?\?)[^}]*)?\}`)
	safe := map[string]bool{ // numeric / locally built values
		"total_ms": true, "duration_ms": true, "offset_ms": true, "trigger_count": true,
		"estimated_minutes": true, "total": true, "valid": true, "unsigned": true,
		"invalid": true, "event_count": true, "length": true,
	}
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		if !strings.Contains(line, "${") {
			continue
		}
		// textContent assignments are not parsed as HTML; escaping would double-encode.
		if i > 0 && strings.HasSuffix(strings.TrimSpace(lines[i-1]), "textContent =") {
			continue
		}
		for _, m := range field.FindAllStringSubmatch(line, -1) {
			parts := strings.Split(strings.ReplaceAll(m[1], "?.", "."), ".")
			if safe[parts[len(parts)-1]] || strings.HasPrefix(m[1], "Math.") {
				continue
			}
			// Only flag reads that are direct, i.e. not already inside escHtml(...).
			if idx := strings.Index(line, m[0]); idx >= 0 && strings.HasSuffix(line[:idx], "escHtml(") {
				continue
			}
			t.Errorf("index.html:%d: unescaped %s", i+1, m[0])
		}
	}
}
