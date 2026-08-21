package common

import (
	"os"
	"strings"
	"sync"

	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/mattn/go-isatty"
	"github.com/projectdiscovery/gologger"
)

var cliParseOutputMu sync.Mutex

const (
	cliOutputText = "text"
	cliOutputJSON = "json"
)

// CLIPresentation describes how a standalone CLI invocation should present
// itself. It intentionally only inspects output flags, so it is safe to call
// before argument parsing, local state creation, or rule loading.
type CLIPresentation struct {
	OutputType   string
	Interactive  bool
	ShowBanner   bool
	NoColor      bool
	SuppressInfo bool
}

// PresentationForArgs is pure so callers can decide presentation before the
// full flag parser performs any initialization. The last recognised output
// flag wins, matching regular command-line flag behaviour.
func PresentationForArgs(args []string, stdoutTTY bool) CLIPresentation {
	outputType := cliOutputText
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "-ot" || arg == "--output-type":
			if index+1 < len(args) {
				outputType = args[index+1]
				index++
			}
		case strings.HasPrefix(arg, "-ot="):
			outputType = strings.TrimPrefix(arg, "-ot=")
		case strings.HasPrefix(arg, "--output-type="):
			outputType = strings.TrimPrefix(arg, "--output-type=")
		}
	}

	interactive := outputType == cliOutputText && stdoutTTY
	return CLIPresentation{
		OutputType:   outputType,
		Interactive:  interactive,
		ShowBanner:   interactive,
		NoColor:      !interactive,
		SuppressInfo: !interactive,
	}
}

// ConfigureCLIPresentation applies the early, standalone CLI presentation
// decision. It must be called before showBanner and full flag parsing.
func ConfigureCLIPresentation(args []string) CLIPresentation {
	presentation := PresentationForArgs(args, stdoutIsTTY())
	gologger.ConfigureCLIOutput(presentation.NoColor, presentation.SuppressInfo)
	ddout.SetUseColor(!presentation.NoColor)
	return presentation
}

func stdoutIsTTY() bool {
	return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
}

// parseCLIFlags keeps usage failures out of a structured/non-interactive
// stdout stream. Text help remains on stdout for normal shell conventions.
func parseCLIFlags(parse func() error, presentation CLIPresentation, args []string) error {
	redirect := presentation.OutputType == cliOutputJSON || (!presentation.Interactive && !cliHelpArgument(args))
	if !redirect {
		return parse()
	}
	cliParseOutputMu.Lock()
	defer cliParseOutputMu.Unlock()
	original := os.Stdout
	os.Stdout = os.Stderr
	defer func() { os.Stdout = original }()
	return parse()
}

func cliHelpArgument(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

// ValidateCLIOutputType enforces the public standalone output enum before
// local state or rule preparation performs filesystem work.
func ValidateCLIOutputType(outputType string) error {
	if outputType == cliOutputText || outputType == cliOutputJSON {
		return nil
	}
	return &CLIUsageError{Message: "-ot/--output-type 仅支持 text 或 json"}
}

// CLIUsageError identifies an invalid local CLI invocation. The command
// entrypoint maps it to the stable usage exit code without treating it as a
// scanner or Agent failure.
type CLIUsageError struct {
	Message string
}

func (err *CLIUsageError) Error() string {
	return err.Message
}

// Flag retains the fatal-compatible legacy entrypoint.
func Flag() {
	if err := FlagWithError(); err != nil {
		gologger.Fatal().Msg(err.Error())
	}
}
