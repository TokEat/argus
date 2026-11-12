package gopocs

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

type moduleFilter struct {
	enabled bool
	tasks   map[string]struct{}
}

var goPocModuleAliases = map[string][]string{
	"adb":                 {"ADB-Scan"},
	"amqp":                {"RabbitMQ-AMQP-Scan"},
	"cassandra":           {"Cassandra-Scan"},
	"clickhouse":          {"ClickHouse-Scan"},
	"dm":                  {"DM-Scan"},
	"epmd":                {"EPMD-Scan"},
	"ftp":                 {"FTP-Crack"},
	"jdwp":                {"JDWP-Scan"},
	"kingbase":            {"Kingbase-Scan"},
	"ldap":                {"LDAP-Scan"},
	"memcache":            {"Memcache-Crack"},
	"memcached":           {"Memcache-Crack"},
	"mongo":               {"MongoDB-Crack"},
	"mongodb":             {"MongoDB-Crack"},
	"mqtt":                {"MQTT-Scan"},
	"mssql":               {"Mssql-Crack"},
	"mysql":               {"Mysql-Crack"},
	"netbios":             {"NetBios-GetHostInfo"},
	"oracle":              {"Oracle-Crack"},
	"postgres":            {"PostgreSQL-Crack"},
	"postgresql":          {"PostgreSQL-Crack"},
	"rabbitmq":            {"RabbitMQ-AMQP-Scan"},
	"rdp":                 {"RDP-Crack"},
	"redis":               {"Redis-Crack"},
	"rmi":                 {"RMI-Scan"},
	"rocketmq":            {"RocketMQ-Broker-Scan", "RocketMQ-NameServer-Scan"},
	"rocketmq-broker":     {"RocketMQ-Broker-Scan"},
	"rocketmq-nameserver": {"RocketMQ-NameServer-Scan"},
	"rocketmq-namesrv":    {"RocketMQ-NameServer-Scan"},
	"rpc":                 {"RPC-GetHostInfo"},
	"rsync":               {"Rsync-Scan"},
	"shiro":               {"Shiro-Key-Crack"},
	"smb":                 {"SMB-MS17-010", "SMB-Crack"},
	"sql-server":          {"Mssql-Crack"},
	"sqlserver":           {"Mssql-Crack"},
	"ssh":                 {"SSH-Crack"},
	"telnet":              {"Telnet-Crack", "Telnet-CVE-Scan", "Telnet-Bypass"},
	"telnet-cve":          {"Telnet-CVE-Scan", "Telnet-Bypass"},
	"viewstate":           {"ViewState-Key-Crack"},
	"vnc":                 {"VNC-Scan"},
	"zookeeper":           {"Zookeeper-Scan"},
	"zk":                  {"Zookeeper-Scan"},
}

func ValidateModuleFilter(raw string) error {
	_, err := newModuleFilter(raw)
	return err
}

func GoPocModuleHelpList() string {
	return strings.Join(SupportedGoPocModules(), ",")
}

func SupportedGoPocModules() []string {
	modules := make([]string, 0, len(goPocModuleAliases)+2)
	modules = append(modules, "all")
	for module := range goPocModuleAliases {
		modules = append(modules, module)
	}
	sort.Strings(modules)
	return modules
}

func ModuleFilterAllowsTask(raw, taskName string) (bool, error) {
	filter, err := newModuleFilter(raw)
	if err != nil {
		return false, err
	}
	return filter.allows(taskName), nil
}

func newModuleFilter(raw string) (moduleFilter, error) {
	tokens := splitModuleFilter(raw)
	if len(tokens) == 0 {
		return moduleFilter{}, nil
	}

	allowed := make(map[string]struct{})
	unknown := make([]string, 0)
	for _, token := range tokens {
		normalized := normalizeModuleToken(token)
		if normalized == "" {
			continue
		}
		if normalized == "*" || normalized == "all" {
			return moduleFilter{}, nil
		}
		plugins := pluginsForModuleToken(normalized)
		if len(plugins) == 0 {
			unknown = append(unknown, token)
			continue
		}
		for _, plugin := range plugins {
			allowed[plugin] = struct{}{}
		}
	}
	if len(unknown) > 0 {
		return moduleFilter{}, fmt.Errorf("不支持的 GoPoc 模块: %s; 支持的模块示例: %s", strings.Join(unknown, ","), strings.Join(supportedGoPocModuleExamples(), ","))
	}
	if len(allowed) == 0 {
		return moduleFilter{}, nil
	}
	return moduleFilter{enabled: true, tasks: allowed}, nil
}

func (filter moduleFilter) allows(taskName string) bool {
	if !filter.enabled {
		return true
	}
	_, ok := filter.tasks[taskName]
	return ok
}

func splitModuleFilter(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || unicode.IsSpace(r)
	})
}

func pluginsForModuleToken(token string) []string {
	if plugins, ok := goPocModuleAliases[token]; ok {
		return plugins
	}
	for plugin := range PluginList {
		if normalizeModuleToken(plugin) == token {
			return []string{plugin}
		}
	}
	return nil
}

func normalizeModuleToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	return value
}

func supportedGoPocModuleExamples() []string {
	examples := []string{"ssh", "ftp", "mysql", "mssql", "redis", "smb", "telnet", "rocketmq", "rabbitmq", "epmd", "cassandra", "clickhouse"}
	sort.Strings(examples)
	return examples
}
