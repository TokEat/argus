package formatter

import (
	"bytes"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger/levels"
)

// CLI is a formatter for outputting CLI logs
type CLI struct {
	NoUseColors bool
	aurora      aurora.Aurora
}

var _ Formatter = &CLI{}

// NewCLI returns a new CLI based formatter
func NewCLI(noUseColors bool) *CLI {
	return &CLI{NoUseColors: noUseColors, aurora: aurora.NewAurora(!noUseColors)}
}

// Format formats the log event data into bytes
func (c *CLI) Format(event *LogEvent) ([]byte, error) {
	if c.NoUseColors {
		event.Message = stripANSI(event.Message)
		for key, value := range event.Metadata {
			event.Metadata[key] = stripANSI(value)
		}
	}
	c.colorizeLabel(event)

	buffer := &bytes.Buffer{}
	buffer.Grow(len(event.Message))

	label, ok := event.Metadata["label"]
	if label != "" && ok {
		buffer.WriteRune('[')
		buffer.WriteString(label)
		buffer.WriteRune(']')
		buffer.WriteRune(' ')
		delete(event.Metadata, "label")
	}
	timestamp, ok := event.Metadata["timestamp"]
	if timestamp != "" && ok {
		buffer.WriteRune('[')
		buffer.WriteString(timestamp)
		buffer.WriteRune(']')
		buffer.WriteRune(' ')
		delete(event.Metadata, "timestamp")
	}
	buffer.WriteString(event.Message)

	for k, v := range event.Metadata {
		buffer.WriteRune(' ')
		buffer.WriteString(c.colorizeKey(k))
		buffer.WriteRune('=')
		buffer.WriteString(v)
	}
	data := buffer.Bytes()
	return data, nil
}

// stripANSI removes CSI control sequences which may have been embedded by a
// caller using aurora directly. Disabling the formatter's own color output is
// otherwise not sufficient for machine-readable CLI modes.
func stripANSI(value string) string {
	const escape = '\x1b'
	for {
		start := -1
		for i := 0; i < len(value); i++ {
			if value[i] == escape {
				start = i
				break
			}
		}
		if start == -1 {
			return value
		}
		end := start + 1
		if end < len(value) && value[end] == '[' {
			end++
			for end < len(value) {
				if value[end] >= '@' && value[end] <= '~' {
					end++
					break
				}
				end++
			}
		}
		value = value[:start] + value[end:]
	}
}

// colorizeKey colorizes the metadata key if enabled
func (c *CLI) colorizeKey(key string) string {
	if c.NoUseColors {
		return key
	}
	return c.aurora.Bold(key).String()
}

// colorizeLabel colorizes the labels if their exists one and colors are enabled
func (c *CLI) colorizeLabel(event *LogEvent) {
	label := event.Metadata["label"]
	if label == "" || c.NoUseColors {
		return
	}
	switch event.Level {
	case levels.LevelSilent:
		return
	case levels.LevelInfo, levels.LevelVerbose:
		event.Metadata["label"] = c.aurora.Blue(label).String()
	case levels.LevelFatal:
		event.Metadata["label"] = c.aurora.Bold(aurora.Red(label)).String()
	case levels.LevelError:
		event.Metadata["label"] = c.aurora.Red(label).String()
	case levels.LevelDebug:
		event.Metadata["label"] = c.aurora.Magenta(label).String()
	case levels.LevelWarning:
		event.Metadata["label"] = c.aurora.Yellow(label).String()
	}
}
