package structs

import (
	"runtime"

	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
)

// DefaultConfig returns the shared safe scan baseline for non-flag callers.
// Active POC and credential checks require an explicit CLI flag or a confirmed
// risk-validation task; omitted fields must never enable them implicitly.
func DefaultConfig() Config {
	cfg := Config{
		Ports:                      scanpolicy.Common100Ports,
		PortScanType:               "tcp",
		TCPPortScanThreads:         1000,
		SYNPortScanThreads:         10000,
		PortsThreshold:             300,
		TCPPortScanTimeout:         6,
		PortScanScatter:            false,
		PortScanProbeInterval:      scanpolicy.DefaultPacingIntervalMillis,
		MasscanPath:                "masscan",
		GetBannerThreads:           500,
		GetBannerTimeout:           5,
		SubdomainBruteForceThreads: 150,
		SubdomainBruteforceDepth:   1,
		WebThreads:                 200,
		WebTimeout:                 10,
		HTTPProxyTest:              true,
		HTTPProxyTestURL:           "https://www.baidu.com",
		HunterPageSize:             100,
		HunterMaxPageCount:         10,
		FofaMaxCount:               100,
		QuakeSize:                  100,
		OutputFile:                 "result.txt",
		OutputType:                 "text",
		NoInteractsh:               true,
		WAFBypassHeaders:           true,
		WAFSkipOnManyFingerprints:  true,
		NoSubdomainBruteForce:      true,
		NoSubFinder:                true,
		NoHostBind:                 true,
		GoPocThreads:               50,
		NoPoc:                      true,
		GolangPoc:                  false,
		DisableGeneralPoc:          true,
		NucleiTemplate:             "config/pocs",
		WorkflowYamlPath:           "config/workflow.yaml",
		FingerConfigFilePath:       "config/finger.yaml",
		DirSearchYaml:              "config/dir.yaml",
		SubdomainWordListFile:      "config/subdomains.txt",
	}

	if runtime.GOOS == "linux" {
		cfg.TCPPortScanThreads = 4000
	}

	return cfg
}
