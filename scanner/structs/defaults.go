package structs

import "runtime"

// DefaultConfig returns the shared safe scan baseline for non-flag callers.
// Active POC and credential checks require an explicit CLI flag or a confirmed
// risk-validation task; omitted fields must never enable them implicitly.
func DefaultConfig() Config {
	cfg := Config{
		Ports:                      "21,22,23,25,53,69,80,81,88,110,111,135,137,139,143,161,179,389,443,445,465,500,514,548,554,587,636,873,993,995,1025,1080,1099,1194,1433,1521,1723,1900,2049,2082,2083,2121,2181,2222,2375,2379,2601,3000,3128,3306,3389,3690,4443,4848,5000,5236,5432,5555,5601,5632,5800,5900,5901,5984,5985,6000,6379,7001,7002,7080,8000,8001,8008,8009,8080,8081,8088,8089,8090,8161,8443,8848,8888,9000,9001,9043,9090,9091,9200,9300,9418,10000,11211,27017,27018,50000,50070,54321",
		PortScanType:               "tcp",
		TCPPortScanThreads:         1000,
		SYNPortScanThreads:         10000,
		PortsThreshold:             300,
		TCPPortScanTimeout:         6,
		MasscanPath:                "masscan",
		GetBannerThreads:           500,
		GetBannerTimeout:           5,
		SubdomainBruteForceThreads: 150,
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
