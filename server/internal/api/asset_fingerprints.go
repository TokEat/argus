package api

import (
	"net/url"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

type assetFingerprintMatch struct {
	ProductName string `json:"ProductName"`
	Source      string `json:"Source,omitempty"`
	SourceLabel string `json:"SourceLabel,omitempty"`
	MatchedURL  string `json:"MatchedURL,omitempty"`
}

type assetWithFingerprints struct {
	db.Asset
	Fingerprints []assetFingerprintMatch `json:"Fingerprints,omitempty"`
}

func attachAssetFingerprints(c *gin.Context, assets []db.Asset, resolutions []assetResolution) ([]assetWithFingerprints, error) {
	out := make([]assetWithFingerprints, len(assets))
	for i, asset := range assets {
		out[i] = assetWithFingerprints{Asset: asset}
	}
	if len(assets) == 0 {
		return out, nil
	}

	lookupKeys := make([]string, 0, len(assets)*2)
	identitiesByAsset := make([][]string, len(assets))
	hasWeb := false
	for i, asset := range assets {
		if assetKindForProtocol(asset.Protocol) != assetKindWeb {
			continue
		}
		hasWeb = true
		identities := assetEndpointIdentities(asset, resolutions)
		identitiesByAsset[i] = identities
		lookupKeys = append(lookupKeys, assetFingerprintLookupKeys(asset, resolutions)...)
	}
	if !hasWeb {
		return out, nil
	}

	hits, err := loadFingerprintsForAssetPage(c, mergeUniqueSorted(nil, lookupKeys))
	if err != nil {
		return nil, err
	}
	byIdentity := make(map[string][]db.FingerprintHit, len(hits))
	for _, hit := range hits {
		identity := endpointIdentity(hit.Target)
		if identity == "" {
			continue
		}
		byIdentity[identity] = append(byIdentity[identity], hit)
	}

	for i, identities := range identitiesByAsset {
		if len(identities) == 0 {
			continue
		}
		seen := make(map[string]assetFingerprintMatch, 4)
		for _, identity := range identities {
			for _, hit := range byIdentity[identity] {
				source := db.ClassifyFingerprintSource(hit.RuleName, hit.Evidence)
				existing, ok := seen[hit.ProductName]
				if ok && fingerprintSourceRank(existing.Source) >= fingerprintSourceRank(source) {
					continue
				}
				seen[hit.ProductName] = assetFingerprintMatch{
					ProductName: hit.ProductName,
					Source:      source,
					SourceLabel: db.FingerprintSourceLabel(source),
					MatchedURL:  db.FingerprintMatchedURL(hit.Target, hit.Evidence),
				}
			}
		}
		if len(seen) == 0 {
			continue
		}
		names := make([]string, 0, len(seen))
		for name := range seen {
			names = append(names, name)
		}
		sort.Strings(names)
		matches := make([]assetFingerprintMatch, 0, len(names))
		for _, name := range names {
			matches = append(matches, seen[name])
		}
		out[i].Fingerprints = matches
	}
	return out, nil
}

func loadFingerprintsForAssetPage(c *gin.Context, keys []string) ([]db.FingerprintHit, error) {
	query := db.DB.Model(&db.FingerprintHit{}).Where("tenant_id = ?", currentTenantID(c))
	query, _ = applyProjectScope(c, query, "project_id")
	if taskID := strings.TrimSpace(c.Query("task_id")); taskID != "" {
		query = applyTaskResultScope(c, query, taskID, reportResultFingerprint)
	} else if len(keys) > 0 {
		query = query.Where("target IN ?", keys)
	} else {
		return nil, nil
	}
	var hits []db.FingerprintHit
	if err := query.Select("target", "product_name", "rule_name", "evidence").Find(&hits).Error; err != nil {
		return nil, err
	}
	return hits, nil
}

func assetFingerprintLookupKeys(asset db.Asset, resolutions []assetResolution) []string {
	keys := make([]string, 0, 4)
	for _, raw := range []string{asset.Target, asset.URL} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		keys = append(keys, raw, db.ResultTargetKey(raw))
		host := extractHost(raw)
		port := endpointPort(raw)
		for _, related := range relatedHostsFor(host, resolutions) {
			if retargeted := retargetEndpoint(raw, related, port); retargeted != "" {
				keys = append(keys, retargeted)
			}
		}
	}
	return mergeUniqueSorted(nil, keys)
}

func assetEndpointIdentities(asset db.Asset, resolutions []assetResolution) []string {
	identities := make([]string, 0, 4)
	for _, raw := range []string{asset.Target, asset.URL} {
		identity := endpointIdentity(raw)
		if identity == "" {
			continue
		}
		identities = append(identities, identity)
		host, port := splitEndpointIdentity(identity)
		for _, related := range relatedHostsFor(host, resolutions) {
			relatedID := strings.ToLower(strings.TrimSpace(related))
			if port != "" {
				relatedID += "|" + port
			}
			identities = append(identities, relatedID)
		}
	}
	return mergeUniqueSorted(nil, identities)
}

func endpointIdentity(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	normalized := db.ResultTargetKey(raw)
	if parsed, err := url.Parse(normalized); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname()) + "|" + parsed.Port()
	}
	return strings.ToLower(raw)
}

func splitEndpointIdentity(identity string) (string, string) {
	host, port, ok := strings.Cut(identity, "|")
	if !ok {
		return identity, ""
	}
	return host, port
}

func endpointPort(raw string) string {
	_, port := splitEndpointIdentity(endpointIdentity(raw))
	return port
}

func retargetEndpoint(raw, host, port string) string {
	raw = strings.TrimSpace(raw)
	host = strings.TrimSpace(host)
	if raw == "" || host == "" {
		return ""
	}
	normalized := db.ResultTargetKey(raw)
	parsed, err := url.Parse(normalized)
	if err != nil || parsed.Scheme == "" {
		return ""
	}
	if port == "" {
		port = parsed.Port()
	}
	if port == "" {
		return parsed.Scheme + "://" + host
	}
	return parsed.Scheme + "://" + host + ":" + port
}

func relatedHostsFor(host string, resolutions []assetResolution) []string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || len(resolutions) == 0 {
		return nil
	}
	related := make([]string, 0)
	for _, row := range resolutions {
		domain := strings.ToLower(strings.TrimSpace(row.Domain))
		if domain == host {
			related = append(related, row.IPs...)
			continue
		}
		for _, ip := range row.IPs {
			if strings.EqualFold(strings.TrimSpace(ip), host) {
				related = append(related, row.Domain)
			}
		}
	}
	return mergeUniqueSorted(nil, related)
}

func fingerprintSourceRank(source string) int {
	switch source {
	case db.FingerprintSourceDirectory:
		return 3
	case db.FingerprintSourceBehavior:
		return 2
	case db.FingerprintSourceFallback:
		return 1
	default:
		return 0
	}
}
