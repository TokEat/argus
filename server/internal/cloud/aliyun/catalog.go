package aliyun

import (
	"fmt"

	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	"github.com/alibabacloud-go/tea/tea"
)

// AvailableInstanceType 可用实例规格（含库存状态）
type AvailableInstanceType struct {
	ID       string  `json:"id"`        // ecs.c7.large
	CPU      int     `json:"cpu"`       // vCPU 核数
	MemoryGB float64 `json:"memory_gb"` // 内存 GB
	Family   string  `json:"family"`    // ecs.c7
	Status   string  `json:"status"`    // WithStock / ClosedWithStock
}

// QueryAvailableInstanceTypes 查询当前地域下有库存的实例规格列表
func (p *ECSProvider) QueryAvailableInstanceTypes(spotStrategy string) ([]AvailableInstanceType, error) {
	// 主流系列（含 ecs.e 经济型——创建时若镜像不兼容会自动查找兼容镜像）
	families := []string{"ecs.c7", "ecs.c8y", "ecs.c8i", "ecs.g7", "ecs.g8y", "ecs.r7", "ecs.e", "ecs.u1", "ecs.c6", "ecs.g6"}

	// 1. 查询可用资源（带库存状态）
	stockMap := make(map[string]string) // instanceType -> statusCategory
	req := &ecs.DescribeAvailableResourceRequest{
		RegionId:            tea.String(p.regionId),
		DestinationResource: tea.String("InstanceType"),
		InstanceChargeType:  tea.String("PostPaid"),
		NetworkCategory:     tea.String("vpc"),
	}
	if spotStrategy != "" && spotStrategy != "NoSpot" {
		req.SpotStrategy = tea.String(spotStrategy)
	}

	res, err := p.client.DescribeAvailableResource(req)
	if err != nil {
		return nil, fmt.Errorf("DescribeAvailableResource: %w", err)
	}
	if res == nil || res.Body == nil {
		return nil, fmt.Errorf("DescribeAvailableResource: empty response")
	}
	if res.Body.AvailableZones != nil {
		for _, az := range res.Body.AvailableZones.AvailableZone {
			status := ""
			if az.StatusCategory != nil {
				status = *az.StatusCategory
			}
			if status != "WithStock" && status != "ClosedWithStock" && status != "" {
				continue
			}
			if az.AvailableResources == nil {
				continue
			}
			for _, ar := range az.AvailableResources.AvailableResource {
				if ar.SupportedResources == nil {
					continue
				}
				for _, sr := range ar.SupportedResources.SupportedResource {
					if sr.Value == nil {
						continue
					}
					srStatus := "WithStock"
					if sr.StatusCategory != nil {
						srStatus = *sr.StatusCategory
					}
					if srStatus == "WithStock" || srStatus == "ClosedWithStock" {
						// 保留最好的库存状态
						existing, ok := stockMap[*sr.Value]
						if !ok || existing == "ClosedWithStock" {
							stockMap[*sr.Value] = srStatus
						}
					}
				}
			}
		}
	}

	// 2. 查询实例规格详情（CPU/内存）
	var result []AvailableInstanceType
	seen := make(map[string]bool)

	for _, family := range families {
		itReq := &ecs.DescribeInstanceTypesRequest{InstanceTypeFamily: tea.String(family)}
		itRes, err := p.client.DescribeInstanceTypes(itReq)
		if err != nil || itRes.Body == nil || itRes.Body.InstanceTypes == nil {
			continue
		}
		for _, it := range itRes.Body.InstanceTypes.InstanceType {
			if it.InstanceTypeId == nil {
				continue
			}
			typeID := *it.InstanceTypeId
			if seen[typeID] {
				continue
			}

			cpu := int32(0)
			if it.CpuCoreCount != nil {
				cpu = *it.CpuCoreCount
			}
			mem := float32(0)
			if it.MemorySize != nil {
				mem = *it.MemorySize
			}

			// 推荐列表允许 1 核入门规格，保留原有上限以避免返回大型规格噪音。
			if cpu < 1 || cpu > 16 {
				continue
			}

			// 检查库存
			status, hasStock := stockMap[typeID]
			if !hasStock {
				continue // 跳过无库存的规格
			}

			seen[typeID] = true
			result = append(result, AvailableInstanceType{
				ID:       typeID,
				CPU:      int(cpu),
				MemoryGB: float64(mem),
				Family:   family,
				Status:   status,
			})
		}
	}

	return result, nil
}
