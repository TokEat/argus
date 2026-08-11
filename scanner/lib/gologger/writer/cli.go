package writer

import (
	"os"
	"sync"

	"github.com/projectdiscovery/gologger/levels"
)

// CLI is a concurrent output writer to terminal.
type CLI struct {
	mutex        *sync.Mutex
	suppressInfo bool
}

var _ Writer = &CLI{}

// NewCLI returns a new CLI concurrent log writer.
func NewCLI() *CLI {
	return &CLI{mutex: &sync.Mutex{}}
}

// NewCLIWithOptions creates a terminal writer for an explicitly configured
// command-line client. The default logger keeps using NewCLI so services such
// as the Agent retain their existing presentation.
func NewCLIWithOptions(suppressInfo bool) *CLI {
	return &CLI{mutex: &sync.Mutex{}, suppressInfo: suppressInfo}
}

// WriteString writes an output to the underlying file
func (w *CLI) Write(data []byte, level levels.Level) {
	if w.suppressInfo && level == levels.LevelInfo {
		return
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()

	switch level {
	case levels.LevelSilent:
		os.Stdout.Write(data)
		os.Stdout.Write([]byte("\n"))
	default:
		os.Stderr.Write(data)
		os.Stderr.Write([]byte("\n"))
	}
}
