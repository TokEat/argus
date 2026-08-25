package api

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
	"gorm.io/gorm"
)

const (
	assetKindWeb        = "web"
	assetKindHostPort   = "host_port"
	assetKindDomain     = "domain"
	assetKindResolution = "resolution"
	assetKindOther      = "other"

	maxAssetResolutions = 2000
)

var (
	errUnknownAssetKind = errors.New("unsupported asset kind")

	assetKindProtocols = map[string][]string{
		assetKindWeb:        {"Web", "Domain-Bind"},
		assetKindHostPort:   {"PortScan", "Protocol", "ProtocolCheck", "Nmap", "IPAlive", "Fofa", "Hunter", "Quake"},
		assetKindDomain:     {"Domain", "DNS-SubFinder", "DNS-Brute", "CDN-Domain"},
		assetKindResolution: {"RealIP"},
	}
)

type assetResolution struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips"`
}

type assetResultStats struct {
	Total       int64             `json:"total"`
	Web         int64             `json:"web"`
	HostPort    int64             `json:"host_port"`
	Domain      int64             `json:"domain"`
	Resolution  int64             `json:"resolution"`
	Other       int64             `json:"other"`
	Resolutions []assetResolution `json:"resolutions,omitempty"`
}

func knownAssetKindProtocols() []string {
	out := make([]string, 0, 16)
	for _, protocols := range assetKindProtocols {
		out = append(out, protocols...)
	}
	sort.Strings(out)
	return out
}

func assetKindForProtocol(protocol string) string {
	protocol = strings.TrimSpace(protocol)
	for kind, protocols := range assetKindProtocols {
		for _, candidate := range protocols {
			if candidate == protocol {
				return kind
			}
		}
	}
	return assetKindOther
}

func applyAssetKindFilter(query *gorm.DB, kind string) (*gorm.DB, error) {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return query, nil
	}
	if kind == assetKindOther {
		return query.Where("protocol NOT IN ?", knownAssetKindProtocols()), nil
	}
	protocols, ok := assetKindProtocols[kind]
	if !ok {
		return query, errUnknownAssetKind
	}
	return query.Where("protocol IN ?", protocols), nil
}

func withoutQueryOrder(query *gorm.DB) *gorm.DB {
	if query == nil {
		return nil
	}
	cloned := query.Session(&gorm.Session{})
	if cloned.Statement != nil {
		delete(cloned.Statement.Clauses, "ORDER BY")
	}
	return cloned
}

func collectAssetResultStats(query *gorm.DB) (assetResultStats, error) {
	stats := assetResultStats{}
	if query == nil {
		return stats, nil
	}
	var rows []struct {
		Protocol string `gorm:"column:protocol"`
		Cnt      int64  `gorm:"column:cnt"`
	}
	// 去掉列表查询上的 created_at 排序，避免 PostgreSQL GROUP BY 失败。
	if err := withoutQueryOrder(query).
		Model(&db.Asset{}).
		Select("protocol, count(*) as cnt").
		Group("protocol").
		Order("protocol").
		Scan(&rows).Error; err != nil {
		return stats, err
	}
	for _, row := range rows {
		stats.Total += row.Cnt
		switch assetKindForProtocol(row.Protocol) {
		case assetKindWeb:
			stats.Web += row.Cnt
		case assetKindHostPort:
			stats.HostPort += row.Cnt
		case assetKindDomain:
			stats.Domain += row.Cnt
		case assetKindResolution:
			stats.Resolution += row.Cnt
		default:
			stats.Other += row.Cnt
		}
	}
	resolutions, err := loadAssetResolutions(query)
	if err != nil {
		return stats, err
	}
	stats.Resolutions = resolutions
	return stats, nil
}

func loadAssetResolutions(query *gorm.DB) ([]assetResolution, error) {
	if query == nil {
		return nil, nil
	}
	var rows []db.Asset
	if err := withoutQueryOrder(query).
		Model(&db.Asset{}).
		Select("target", "tags").
		Where("protocol = ?", "RealIP").
		Order("target").
		Limit(maxAssetResolutions).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]assetResolution, 0, len(rows))
	seen := make(map[string]int, len(rows))
	for _, row := range rows {
		domain, ips := parseRealIPAsset(row.Target, row.Tags)
		if domain == "" || len(ips) == 0 {
			continue
		}
		if idx, ok := seen[domain]; ok {
			out[idx].IPs = mergeUniqueSorted(out[idx].IPs, ips)
			continue
		}
		seen[domain] = len(out)
		sort.Strings(ips)
		out = append(out, assetResolution{Domain: domain, IPs: ips})
	}
	return out, nil
}

func parseRealIPAsset(target, tags string) (string, []string) {
	var payload struct {
		Domain string      `json:"domain"`
		IPs    interface{} `json:"ips"`
	}
	domain := ""
	ips := make([]string, 0)
	if strings.TrimSpace(tags) != "" {
		_ = json.Unmarshal([]byte(tags), &payload)
		domain = strings.TrimSpace(payload.Domain)
		switch typed := payload.IPs.(type) {
		case []interface{}:
			for _, item := range typed {
				if value, ok := item.(string); ok {
					value = strings.TrimSpace(value)
					if value != "" {
						ips = append(ips, value)
					}
				}
			}
		case []string:
			for _, value := range typed {
				value = strings.TrimSpace(value)
				if value != "" {
					ips = append(ips, value)
				}
			}
		}
	}
	if domain == "" {
		domain = strings.TrimSpace(target)
	}
	return domain, mergeUniqueSorted(nil, ips)
}

func mergeUniqueSorted(dst, extra []string) []string {
	seen := make(map[string]struct{}, len(dst)+len(extra))
	out := make([]string, 0, len(dst)+len(extra))
	for _, value := range append(append([]string{}, dst...), extra...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
