package scanpolicy

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

type CredentialService struct {
	Plugin   string   `json:"plugin"`
	Services []string `json:"services"`
	Ports    []int    `json:"ports"`
}

// CredentialServices is the control-plane allowlist. HTTP is deliberately
// absent; adding a service is a reviewed contract change shared by Server and
// Scanner rather than a free-form user input.
var CredentialServices = []CredentialService{
	{Plugin: "SSH-Crack", Services: []string{"ssh"}, Ports: []int{22}},
	{Plugin: "FTP-Crack", Services: []string{"ftp"}, Ports: []int{21}},
	{Plugin: "Mysql-Crack", Services: []string{"mysql"}, Ports: []int{3306}},
	{Plugin: "Mssql-Crack", Services: []string{"mssql", "sqlserver"}, Ports: []int{1433}},
	{Plugin: "Oracle-Crack", Services: []string{"oracle"}, Ports: []int{1521}},
	{Plugin: "RDP-Crack", Services: []string{"rdp"}, Ports: []int{3389}},
	{Plugin: "Redis-Crack", Services: []string{"redis"}, Ports: []int{6379}},
	{Plugin: "SMB-Crack", Services: []string{"smb"}, Ports: []int{445}},
	{Plugin: "PostgreSQL-Crack", Services: []string{"postgresql", "postgres"}, Ports: []int{5432}},
	{Plugin: "Telnet-Crack", Services: []string{"telnet"}, Ports: []int{23}},
	{Plugin: "VNC-Scan", Services: []string{"vnc"}, Ports: []int{5900, 5901}},
	{Plugin: "Rsync-Scan", Services: []string{"rsync"}, Ports: []int{873}},
	{Plugin: "DM-Scan", Services: []string{"dm"}, Ports: []int{5236}},
	{Plugin: "Kingbase-Scan", Services: []string{"kingbase"}, Ports: []int{54321}},
}

type CredentialTargetPlan struct {
	Endpoint    string `json:"endpoint"`
	Service     string `json:"service"`
	Plugin      string `json:"plugin"`
	Eligibility string `json:"eligibility"`
}

// ResolveCredentialTarget applies protocol evidence first, then standard-port
// fallback only when the protocol is unknown. It never treats HTTP(S) as a
// generic credential target.
func ResolveCredentialTarget(host string, port int, observedService string) (CredentialTargetPlan, bool) {
	service := strings.ToLower(strings.TrimSpace(observedService))
	if service == "http" || service == "https" || port < 1 || port > 65535 {
		return CredentialTargetPlan{}, false
	}
	for _, descriptor := range CredentialServices {
		for _, candidate := range descriptor.Services {
			if service != "" && service == candidate {
				return CredentialTargetPlan{Endpoint: net.JoinHostPort(host, strconv.Itoa(port)), Service: service, Plugin: descriptor.Plugin, Eligibility: "protocol"}, true
			}
		}
	}
	if service != "" && service != "unknown" && service != "unidentified" {
		return CredentialTargetPlan{}, false
	}
	for _, descriptor := range CredentialServices {
		for _, candidate := range descriptor.Ports {
			if port == candidate {
				return CredentialTargetPlan{Endpoint: net.JoinHostPort(host, strconv.Itoa(port)), Service: service, Plugin: descriptor.Plugin, Eligibility: "standard_port"}, true
			}
		}
	}
	return CredentialTargetPlan{}, false
}

func SortedCredentialServices() []CredentialService {
	items := append([]CredentialService(nil), CredentialServices...)
	sort.Slice(items, func(i, j int) bool { return items[i].Plugin < items[j].Plugin })
	return items
}
