package main

import (
	"fmt"
	"io"

	"github.com/P0lar1ght/argus/scanner/common"
)

// dispatchEarlyCLI handles metadata that must run before Arsenal preparation
// or scan initialization.
func dispatchEarlyCLI(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(stdout, common.CLIVersionString())
		return true, 0
	}
	return false, 0
}
