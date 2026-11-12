package ddout

import (
	"strings"

	"github.com/logrusorgru/aurora"
)

var useColor bool

// SetUseColor toggles ANSI highlighting for interactive text stdout.
// Files and JSON stay uncolored.
func SetUseColor(enabled bool) {
	useColor = enabled
}

func colorizeFindingLine(line string) string {
	if !useColor || line == "" {
		return line
	}
	au := aurora.NewAurora(true)
	parts := strings.Split(line, "\n")
	for i, part := range parts {
		parts[i] = colorizeFindingSegment(au, part)
	}
	return strings.Join(parts, "\n")
}

func colorizeFindingSegment(au aurora.Aurora, line string) string {
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	rest := line[i:]
	if !strings.HasPrefix(rest, "[") {
		return line
	}
	end := strings.IndexByte(rest, ']')
	if end < 2 {
		return line
	}
	tag := rest[1:end]
	colored := colorBracketTag(au, tag)
	return line[:i] + colored + colorInlineServiceTags(au, rest[end+1:])
}

func colorInlineServiceTags(au aurora.Aurora, rest string) string {
	trimmed := strings.TrimLeft(rest, " \t")
	if !strings.HasPrefix(trimmed, "[") {
		return rest
	}
	pad := rest[:len(rest)-len(trimmed)]
	end := strings.IndexByte(trimmed, ']')
	if end < 2 {
		return rest
	}
	tag := strings.ToLower(trimmed[1:end])
	switch tag {
	case "tcp", "udp", "web", "other":
		return pad + colorBracketTag(au, tag) + trimmed[end+1:]
	default:
		return rest
	}
}

func colorBracketTag(au aurora.Aurora, tag string) string {
	wrapped := "[" + tag + "]"
	switch strings.ToLower(tag) {
	case "alive":
		return au.BrightGreen(wrapped).String()
	case "port", "tcp", "udp", "other":
		return au.BrightCyan(wrapped).String()
	case "web":
		return au.BrightBlue(wrapped).Bold().String()
	case "finger":
		return au.Magenta(wrapped).Bold().String()
	case "certificates", "code", "size", "redirect", "title":
		return au.Blue(wrapped).String()
	case "poc":
		return au.BrightRed(wrapped).Bold().String()
	case "path", "topo":
		return au.Yellow(wrapped).String()
	case "domain", "domain-bind":
		return au.Cyan(wrapped).String()
	default:
		return au.Bold(wrapped).String()
	}
}
