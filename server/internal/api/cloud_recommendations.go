package api

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/P0lar1ght/argus/server/internal/cloud/aliyun"
	"github.com/P0lar1ght/argus/server/internal/db"
)

type cloudRecommendationItem struct {
	Region        string  `json:"region"`
	RegionName    string  `json:"region_name,omitempty"`
	InstanceType  string  `json:"instance_type"`
	CPU           int     `json:"cpu"`
	MemoryGB      float64 `json:"memory_gb"`
	Family        string  `json:"family"`
	Status        string  `json:"status"`
	InstancePrice float64 `json:"instance_price"`
	SpotPrice     float64 `json:"spot_price"`
	TotalHourly   float64 `json:"total_hourly"`
	Currency      string  `json:"currency"`
	PriceUnit     string  `json:"price_unit"`
	PriceSource   string  `json:"price_source"`
}

type cloudRecommendationResult struct {
	Recommendations  []cloudRecommendationItem `json:"recommendations"`
	Cheapest         *cloudRecommendationItem  `json:"cheapest,omitempty"`
	Warnings         []string                  `json:"warnings,omitempty"`
	RegionsScanned   int                       `json:"regions_scanned"`
	RegionsSucceeded int                       `json:"regions_succeeded"`
	RegionsFailed    int                       `json:"regions_failed"`
	PriceRequests    int                       `json:"price_requests"`
}

const (
	maxRecommendationTypesPerRegion = 12
	maxRecommendationPriceRequests  = 192
)

type recommendationPriceBudget struct {
	mu    sync.Mutex
	used  int
	limit int
}

func (b *recommendationPriceBudget) acquire() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used >= b.limit {
		return false
	}
	b.used++
	return true
}

func (b *recommendationPriceBudget) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

func economicalRecommendationTypes(types []aliyun.AvailableInstanceType) []aliyun.AvailableInstanceType {
	filtered := make([]aliyun.AvailableInstanceType, 0, len(types))
	seen := make(map[string]struct{}, len(types))
	for _, instanceType := range types {
		if instanceType.ID == "" || instanceType.CPU < 1 || instanceType.CPU > 4 || instanceType.MemoryGB <= 0 || instanceType.MemoryGB > 16 {
			continue
		}
		if _, exists := seen[instanceType.ID]; exists {
			continue
		}
		seen[instanceType.ID] = struct{}{}
		filtered = append(filtered, instanceType)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].CPU != filtered[j].CPU {
			return filtered[i].CPU < filtered[j].CPU
		}
		if filtered[i].MemoryGB != filtered[j].MemoryGB {
			return filtered[i].MemoryGB < filtered[j].MemoryGB
		}
		return filtered[i].ID < filtered[j].ID
	})
	if len(filtered) > maxRecommendationTypesPerRegion {
		return filtered[:maxRecommendationTypesPerRegion]
	}
	return filtered
}

func (s *CloudSetupService) CheapestRecommendations(account *db.CloudAccount, accessKeyID, accessKeySecret, regionID, spotStrategy string) (cloudRecommendationResult, error) {
	var result cloudRecommendationResult
	if s.CatalogFactory == nil {
		return result, fmt.Errorf("云资源 Provider 未配置")
	}
	regionID = strings.TrimSpace(regionID)
	if regionID == "" {
		return result, fmt.Errorf("未指定查询地域")
	}
	// 价格查询只针对当前地域，地域列表由单独的 regions 接口负责发现。
	regions := []aliyun.RegionInfo{{RegionID: regionID}}

	// 只对低成本候选计价，并设置全局预算，避免全地域 × 全规格触发大量价格请求。
	type regionResult struct {
		items    []cloudRecommendationItem
		warnings []string
		success  bool
	}
	results := make(chan regionResult, len(regions))
	sem := make(chan struct{}, 3)
	budget := &recommendationPriceBudget{limit: maxRecommendationPriceRequests}
	var wg sync.WaitGroup
	for _, region := range regions {
		if region.RegionID == "" {
			continue
		}
		region := region
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			catalog, createErr := s.CatalogFactory(accessKeyID, accessKeySecret, region.RegionID)
			if createErr != nil || catalog == nil {
				results <- regionResult{warnings: []string{fmt.Sprintf("%s: 创建 Provider 失败", region.RegionID)}}
				return
			}

			queryStrategy := spotStrategy
			types, typeErr := catalog.QueryAvailableInstanceTypes(queryStrategy)
			var warnings []string
			if queryStrategy != "NoSpot" && (typeErr != nil || len(types) == 0) {
				postpaidTypes, postpaidErr := catalog.QueryAvailableInstanceTypes("NoSpot")
				if postpaidErr == nil {
					types = postpaidTypes
					queryStrategy = "NoSpot"
					warnings = append(warnings, fmt.Sprintf("%s: Spot 库存不可用，已回退按量库存", region.RegionID))
				} else {
					message := "Spot 库存查询失败"
					if typeErr == nil {
						message = "未发现 Spot 库存"
					}
					results <- regionResult{warnings: []string{fmt.Sprintf("%s: %s，按量库存查询也失败", region.RegionID, message)}}
					return
				}
			} else if typeErr != nil {
				results <- regionResult{warnings: []string{fmt.Sprintf("%s: 库存查询失败", region.RegionID)}}
				return
			}

			postpaidTypesLoaded := queryStrategy == "NoSpot"
			postpaidTypes := make(map[string]aliyun.AvailableInstanceType)
			if postpaidTypesLoaded {
				for _, item := range types {
					postpaidTypes[item.ID] = item
				}
			}
			loadPostpaidTypes := func() error {
				if postpaidTypesLoaded {
					return nil
				}
				fallbackTypes, fallbackErr := catalog.QueryAvailableInstanceTypes("NoSpot")
				if fallbackErr != nil {
					return fallbackErr
				}
				for _, item := range fallbackTypes {
					postpaidTypes[item.ID] = item
				}
				postpaidTypesLoaded = true
				return nil
			}

			var items []cloudRecommendationItem
			fallbackNoted := false
			for _, instanceType := range economicalRecommendationTypes(types) {
				if !budget.acquire() {
					warnings = append(warnings, fmt.Sprintf("%s: 已达到全局价格请求预算，剩余规格未计价", region.RegionID))
					break
				}
				price, priceErr := catalog.QueryPrice(instanceType.ID, queryStrategy)
				priceSource := "postpaid"
				if queryStrategy != "NoSpot" {
					if priceErr == nil && price != nil && price.SpotPrice > 0 {
						priceSource = "spot"
					} else {
						if fallbackErr := loadPostpaidTypes(); fallbackErr != nil {
							if !fallbackNoted {
								warnings = append(warnings, fmt.Sprintf("%s: Spot 价格不可用，按量库存查询失败", region.RegionID))
								fallbackNoted = true
							}
							continue
						}
						if _, available := postpaidTypes[instanceType.ID]; !available {
							continue
						}
						if !budget.acquire() {
							warnings = append(warnings, fmt.Sprintf("%s: 已达到全局价格请求预算，按量回退未完成", region.RegionID))
							break
						}
						price, priceErr = catalog.QueryPrice(instanceType.ID, "NoSpot")
						priceSource = "postpaid"
						if priceErr == nil && price != nil && price.TotalHourly > 0 && !fallbackNoted {
							warnings = append(warnings, fmt.Sprintf("%s: 部分 Spot 价格不可用，已回退按量价格", region.RegionID))
							fallbackNoted = true
						}
					}
				}
				if priceErr != nil || price == nil {
					continue
				}
				total := price.TotalHourly
				if priceSource == "spot" {
					total = price.SpotPrice
				}
				if total <= 0 {
					continue
				}
				items = append(items, cloudRecommendationItem{
					Region: region.RegionID, RegionName: region.LocalName, InstanceType: instanceType.ID,
					CPU: instanceType.CPU, MemoryGB: instanceType.MemoryGB, Family: instanceType.Family,
					Status: instanceType.Status, InstancePrice: price.InstancePrice, SpotPrice: price.SpotPrice,
					TotalHourly: total, Currency: price.Currency, PriceUnit: price.PriceUnit, PriceSource: priceSource,
				})
			}
			results <- regionResult{items: items, warnings: warnings, success: true}
		}()
	}
	wg.Wait()
	close(results)
	for regionResult := range results {
		result.Recommendations = append(result.Recommendations, regionResult.items...)
		result.Warnings = append(result.Warnings, regionResult.warnings...)
		if regionResult.success {
			result.RegionsSucceeded++
		} else {
			result.RegionsFailed++
		}
	}
	result.RegionsScanned = result.RegionsSucceeded + result.RegionsFailed
	result.PriceRequests = budget.count()
	sort.Slice(result.Recommendations, func(i, j int) bool {
		a, b := result.Recommendations[i], result.Recommendations[j]
		if a.TotalHourly != b.TotalHourly {
			return a.TotalHourly < b.TotalHourly
		}
		if a.CPU != b.CPU {
			return a.CPU > b.CPU
		}
		if a.MemoryGB != b.MemoryGB {
			return a.MemoryGB > b.MemoryGB
		}
		if a.Region != b.Region {
			return a.Region < b.Region
		}
		return a.InstanceType < b.InstanceType
	})
	sort.Strings(result.Warnings)
	if len(result.Recommendations) > 0 {
		result.Cheapest = &result.Recommendations[0]
	}
	return result, nil
}
