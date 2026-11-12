// Command arsenal-package builds the versioned offline runtime rules shipped
// beside standalone CLI binaries. It is intentionally not part of the CLI UI.
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/TokEat/argus/scanner/internal/arsenal"
)

func main() {
	configDir := flag.String("config", "scanner/common/config", "reviewed scanner rule baseline")
	output := flag.String("output", "release/argus-data/arsenal/arsenal.db", "runtime arsenal.db output")
	flag.Parse()

	inspection, err := arsenal.BuildRulePackageFromConfig(*configDir, *output)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("built %s schema=%s version=%s fingerprints=%d pocs=%d workflows=%d dirs=%d\n",
		*output, inspection.SchemaVersion, inspection.RuleVersion,
		inspection.Counts.Fingerprints, inspection.Counts.Pocs, inspection.Counts.Workflows, inspection.Counts.DirProbes)
}
