// Package subdomain 子域名枚举模块。
package subdomain

import (
	"bytes"
	"dddd/scanner/ddout"
	"dddd/scanner/utils"
	_ "embed"
	"io"
	"strings"

	"github.com/projectdiscovery/dnsx/calldnsx"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// Config captures the task-scoped options used by subdomain enumeration.
type Config struct {
	NoSubdomainBruteForce      bool
	NoSubFinder                bool
	SubdomainBruteForceThreads int
	SubdomainWordListFile      string
	EmitFunc                   func(ddout.OutputMessage)
}

// Enumerate runs active and passive subdomain enumeration without relying on
// process-wide globals.
func Enumerate(domains []string, cfg Config) []string {
	var results []string
	dict := embeddedWordlist()

	for _, domain := range domains {
		if domain == "" {
			continue
		}

		if !cfg.NoSubdomainBruteForce {
			results = append(results, calldnsx.CallDNSx(
				domain,
				cfg.SubdomainBruteForceThreads,
				dnsCallback(cfg.EmitFunc),
				dict,
				cfg.SubdomainWordListFile,
			)...)
		}

		if !cfg.NoSubFinder {
			results = append(results, subFinder(domain, cfg.EmitFunc)...)
		}
	}

	results = utils.RemoveDuplicateElement(results)
	return removeEmpty(results)
}

func subFinder(domain string, emit func(ddout.OutputMessage)) []string {
	runnerInstance, err := runner.NewRunner(&runner.Options{
		Threads:            10,
		Timeout:            15,
		MaxEnumerationTime: 5,
		Resolvers:          resolve.DefaultResolvers,
		ResultCallback: func(s *resolve.HostEntry) {
			emitOutput(emit, ddout.OutputMessage{
				Type:          "DNS-SubFinder",
				Domain:        s.Host,
				AdditionalMsg: s.Source,
			})
		},
		RemoveWildcard:     true,
		DisableUpdateCheck: true,
		// Passive discovery remains available, but Scanner and Agent must never
		// load Provider credentials or execute the migrated search providers.
		DisableProviderConfig: true,
		ExcludeSources:        goflags.StringSlice{"fofa", "hunter", "quake"},
	})
	if err != nil {
		gologger.Error().Msgf("[SubFinder] 初始化失败: %v", err)
		return nil
	}

	buf := bytes.Buffer{}
	if err := runnerInstance.EnumerateSingleDomain(domain, []io.Writer{&buf}); err != nil {
		gologger.Error().Msgf("[SubFinder] %s 枚举失败: %v", domain, err)
		return nil
	}

	data, err := io.ReadAll(&buf)
	if err != nil {
		gologger.Error().Msgf("[SubFinder] %s 读取结果失败: %v", domain, err)
		return nil
	}

	return removeEmpty(strings.Split(string(data), "\n"))
}

func dnsCallback(emit func(ddout.OutputMessage)) func(string) {
	return func(subdomain string) {
		emitOutput(emit, ddout.OutputMessage{
			Type:   "DNS-Brute",
			Domain: subdomain,
		})
	}
}

func emitOutput(emit func(ddout.OutputMessage), msg ddout.OutputMessage) {
	if emit != nil {
		emit(msg)
		return
	}
	ddout.FormatOutput(msg)
}

//go:embed subdomains.txt
var embedSubdomainDict string

func embeddedWordlist() []string {
	t := strings.ReplaceAll(embedSubdomainDict, "\r\n", "\n")
	return removeEmpty(strings.Split(t, "\n"))
}

func removeEmpty(input []string) []string {
	if len(input) == 0 {
		return nil
	}

	result := make([]string, 0, len(input))
	for _, item := range input {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		result = append(result, item)
	}
	return result
}
