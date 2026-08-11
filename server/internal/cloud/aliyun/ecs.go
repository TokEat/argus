package aliyun

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/cloud"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	"github.com/alibabacloud-go/tea/tea"
)

func init() {
	cloud.RegisterProviderFactory("aliyun", func(akID, akSecret, region string) (cloud.CloudProvider, error) {
		return NewECSProvider(akID, akSecret, region)
	})
}

type ECSProvider struct {
	client   *ecs.Client
	regionId string
	akID     string
	akSecret string
}

func NewECSProvider(accessKeyId, accessKeySecret, regionId string) (*ECSProvider, error) {
	// 当 regionId 为空时，使用全局 Endpoint 用于 DescribeRegions 等不依赖地域的查询
	endpoint := "ecs.aliyuncs.com"
	if regionId != "" {
		endpoint = fmt.Sprintf("ecs.%s.aliyuncs.com", regionId)
	}
	config := &openapi.Config{
		AccessKeyId:     tea.String(accessKeyId),
		AccessKeySecret: tea.String(accessKeySecret),
		Endpoint:        tea.String(endpoint),
	}
	client, err := ecs.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &ECSProvider{
		client:   client,
		regionId: regionId,
		akID:     accessKeyId,
		akSecret: accessKeySecret,
	}, nil
}

// RegionInfo 可用地域信息
type RegionInfo struct {
	RegionID  string `json:"region_id"`
	LocalName string `json:"local_name"`
	Endpoint  string `json:"endpoint"`
}

// DiscoverRegions 查询阿里云所有可用 Region
func (p *ECSProvider) DiscoverRegions() ([]RegionInfo, error) {
	req := &ecs.DescribeRegionsRequest{
		AcceptLanguage: tea.String("zh-CN"),
	}
	res, err := p.client.DescribeRegions(req)
	if err != nil {
		return nil, fmt.Errorf("DescribeRegions error: %w", err)
	}

	var regions []RegionInfo
	if res.Body != nil && res.Body.Regions != nil {
		for _, r := range res.Body.Regions.Region {
			regionID := ""
			if r.RegionId != nil {
				regionID = *r.RegionId
			}
			localName := ""
			if r.LocalName != nil {
				localName = *r.LocalName
			}
			endpoint := ""
			if r.RegionEndpoint != nil {
				endpoint = *r.RegionEndpoint
			}
			regions = append(regions, RegionInfo{
				RegionID:  regionID,
				LocalName: localName,
				Endpoint:  endpoint,
			})
		}
	}

	return regions, nil
}

// CreateInstance 创建云实例。优先使用配置的抢占式保留时长（保护期）；
// 若保护期库存不足，自动降级为无保护期抢占式，避免因保护期无库存而创建失败。
func (p *ECSProvider) CreateInstance(cfg cloud.InstanceConfig) (*cloud.Instance, error) {
	spotDuration := cfg.SpotDuration
	if spotDuration < 0 {
		spotDuration = 0
	}
	if spotDuration > 6 {
		spotDuration = 6
	}
	durationsToTry := []int32{spotDuration}
	if spotDuration > 0 && cfg.SpotStrategy != "NoSpot" {
		durationsToTry = append(durationsToTry, 0) // 保护期无库存时退回无保护期抢占式
	}

	var lastErr error
	for _, spotDur := range durationsToTry {
		if spotDur < spotDuration {
			log.Printf("[ECS] 保留时长 %dh 全部无库存，退回无保护期(0h)抢占式重试", spotDuration)
		}
		inst, err := p.createInstanceWithSpotDuration(cfg, spotDur)
		if err == nil {
			return inst, nil
		}
		lastErr = err
		// 账户级致命错误（余额不足/权限等）不再降级重试
		if isFatalCloudError(err.Error()) {
			return nil, err
		}
	}
	return nil, lastErr
}

func (p *ECSProvider) createInstanceWithSpotDuration(cfg cloud.InstanceConfig, spotDur int32) (*cloud.Instance, error) {
	// 自动选择支持该实例规格的可用区 VSwitch + 规格降级，防止 InvalidResourceType.NotSupported
	resolvedVSwitch, resolvedType, err := p.resolveCompatibleVSwitch(cfg)
	if err != nil {
		return nil, fmt.Errorf("resolve compatible VSwitch: %w", err)
	}
	if resolvedType != cfg.InstanceType {
		log.Printf("[ECS] 实例规格从 %s 自动降级为 %s（原规格无库存）", cfg.InstanceType, resolvedType)
	}
	// 用解析后的 VSwitch 作为后续换区的参考
	referenceVSwitch := resolvedVSwitch

	// 构建标签列表
	var tagList []*ecs.RunInstancesRequestTag
	for k, v := range cfg.Tags {
		tagList = append(tagList, &ecs.RunInstancesRequestTag{
			Key:   tea.String(k),
			Value: tea.String(v),
		})
	}

	// 确定竞价策略（默认使用抢占式实例，节省 70-90%）
	spotStrategy := "SpotAsPriceGo"
	spotPriceLimit := float32(0)
	if cfg.MaxPrice > 0 {
		spotStrategy = cfg.SpotStrategy
		spotPriceLimit = float32(cfg.MaxPrice)
	} else if cfg.SpotStrategy != "" {
		spotStrategy = cfg.SpotStrategy
	}

	// 尝试创建实例，NoStock 时自动换区重试
	typesToTry := []string{resolvedType}
	if resolvedType == cfg.InstanceType {
		// 如果没有降级过，准备降级候选
		typesToTry = append(typesToTry, generateFallbackTypes(resolvedType)...)
	}

	var lastErr error
	for _, instType := range typesToTry {
		// 查询该规格的所有可用区
		zones, _ := p.queryAvailableZones(instType, cfg.SpotStrategy)
		if len(zones) == 0 {
			continue
		}

		for _, zone := range zones {
			// 获取该可用区的 VSwitch
			vsw, err := p.getOrCreateVSwitchForZone(zone, referenceVSwitch)
			if err != nil {
				log.Printf("[ECS] 获取 zone=%s 的 VSwitch 失败: %v, 跳过", zone, err)
				continue
			}

			req := &ecs.RunInstancesRequest{
				RegionId:                tea.String(cfg.Region),
				ImageId:                 tea.String(cfg.ImageID),
				InstanceType:            tea.String(instType),
				SecurityGroupId:         tea.String(cfg.SecurityGroup),
				VSwitchId:               tea.String(vsw),
				UserData:                tea.String(cfg.UserData),
				InstanceChargeType:      tea.String("PostPaid"),
				InternetChargeType:      tea.String("PayByTraffic"),
				InternetMaxBandwidthOut: tea.Int32(100),
				Amount:                  tea.Int32(1),
				SpotStrategy:            tea.String(spotStrategy),
			}
			req.SystemDisk = &ecs.RunInstancesRequestSystemDisk{
				Category: tea.String("cloud_essd"),
			}
			// 抢占式保留时长（保护期）：spotDur=0 表示无保护期
			if spotStrategy != "NoSpot" && spotStrategy != "" {
				req.SpotDuration = tea.Int32(spotDur)
			}
			if spotPriceLimit > 0 {
				req.SpotPriceLimit = tea.Float32(spotPriceLimit)
			}
			if len(tagList) > 0 {
				req.Tag = tagList
			}

			res, err := p.client.RunInstances(req)
			if err != nil {
				errMsg := err.Error()

				// NotMatch（镜像不兼容）→ 自动查找兼容镜像重试一次
				if strings.Contains(errMsg, "NotMatch") {
					log.Printf("[ECS] %s 镜像不兼容，尝试查找兼容镜像...", instType)
					compatImage := p.findCompatibleImage(instType)
					if compatImage != "" && compatImage != *req.ImageId {
						log.Printf("[ECS] 找到兼容镜像 %s，重试...", compatImage)
						req.ImageId = tea.String(compatImage)
						res2, err2 := p.client.RunInstances(req)
						if err2 == nil && res2 != nil && res2.Body != nil &&
							res2.Body.InstanceIdSets != nil && len(res2.Body.InstanceIdSets.InstanceIdSet) > 0 {
							res = res2
							err = nil
							goto success
						}
						// 兼容镜像也失败
						if err2 != nil {
							log.Printf("[ECS] 兼容镜像 %s 也失败: %v", compatImage, err2)
							// 账户级致命错误 → 立即终止
							if isFatalCloudError(err2.Error()) {
								return nil, fmt.Errorf("RunInstances error: %w", err2)
							}
						}
					}
					lastErr = err
					continue
				}

				// 账户级致命错误（余额不足、权限不够等）→ 立即终止，不要重试
				if isFatalCloudError(errMsg) {
					return nil, fmt.Errorf("RunInstances error: %w", err)
				}

				// NoStock / NotSupported / DiskCategory → 换区/换规格重试
				if strings.Contains(errMsg, "NoStock") ||
					strings.Contains(errMsg, "NotSupported") ||
					strings.Contains(errMsg, "SystemDiskCategory") ||
					strings.Contains(errMsg, "LessThanImageSize") {
					log.Printf("[ECS] %s 在 zone=%s 不兼容(%s)，尝试下一个...", instType, zone, errMsg[:min(len(errMsg), 80)])
					lastErr = err
					continue
				}
				// 其他错误直接返回
				return nil, fmt.Errorf("RunInstances error: %w", err)
			}

		success:

			if len(res.Body.InstanceIdSets.InstanceIdSet) == 0 {
				return nil, fmt.Errorf("no instance ID returned")
			}

			instanceID := *res.Body.InstanceIdSets.InstanceIdSet[0]
			if instType != cfg.InstanceType {
				log.Printf("[ECS] 实例 %s 使用替代规格 %s 在 zone=%s 创建成功", instanceID, instType, zone)
			}

			return &cloud.Instance{
				ID:        instanceID,
				Status:    "Pending",
				CreatedAt: time.Now(),
			}, nil
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("所有可用区和规格均无库存: %w", lastErr)
	}
	return nil, fmt.Errorf("所有可用区和规格均无库存，请更换地域")
}

// getOrCreateVSwitchForZone 获取指定可用区的 VSwitch（优先复用已有的）
func (p *ECSProvider) getOrCreateVSwitchForZone(zone, referenceVSwitch string) (string, error) {
	// 先查 referenceVSwitch 的所在区域
	vswReq := &ecs.DescribeVSwitchesRequest{
		RegionId:  tea.String(p.regionId),
		VSwitchId: tea.String(referenceVSwitch),
	}
	vswRes, err := p.client.DescribeVSwitches(vswReq)
	if err != nil {
		return referenceVSwitch, nil
	}

	currentVPC := ""
	currentZone := ""
	if vswRes.Body != nil && vswRes.Body.VSwitches != nil && len(vswRes.Body.VSwitches.VSwitch) > 0 {
		if vswRes.Body.VSwitches.VSwitch[0].VpcId != nil {
			currentVPC = *vswRes.Body.VSwitches.VSwitch[0].VpcId
		}
		if vswRes.Body.VSwitches.VSwitch[0].ZoneId != nil {
			currentZone = *vswRes.Body.VSwitches.VSwitch[0].ZoneId
		}
	}

	// 如果 referenceVSwitch 就在目标可用区，直接用
	if currentZone == zone {
		return referenceVSwitch, nil
	}

	// 在同 VPC 查找目标可用区的 VSwitch
	if currentVPC != "" {
		allReq := &ecs.DescribeVSwitchesRequest{
			RegionId: tea.String(p.regionId),
			VpcId:    tea.String(currentVPC),
			PageSize: tea.Int32(50),
		}
		allRes, err := p.client.DescribeVSwitches(allReq)
		if err == nil && allRes.Body != nil && allRes.Body.VSwitches != nil {
			for _, v := range allRes.Body.VSwitches.VSwitch {
				if v.ZoneId != nil && *v.ZoneId == zone {
					return *v.VSwitchId, nil
				}
			}
		}

		// 没有就自动创建
		createReq := &ecs.CreateVSwitchRequest{
			RegionId:    tea.String(p.regionId),
			VpcId:       tea.String(currentVPC),
			ZoneId:      tea.String(zone),
			CidrBlock:   tea.String(p.pickAvailableCIDR(currentVPC)),
			VSwitchName: tea.String(fmt.Sprintf("argus-auto-%s", zone)),
		}
		createRes, err := p.client.CreateVSwitch(createReq)
		if err != nil {
			return "", fmt.Errorf("创建 VSwitch 失败 (zone=%s): %w", zone, err)
		}
		newID := *createRes.Body.VSwitchId
		// 等待可用
		for i := 0; i < 10; i++ {
			time.Sleep(2 * time.Second)
			checkReq := &ecs.DescribeVSwitchesRequest{RegionId: tea.String(p.regionId), VSwitchId: tea.String(newID)}
			checkRes, _ := p.client.DescribeVSwitches(checkReq)
			if checkRes != nil && checkRes.Body != nil && checkRes.Body.VSwitches != nil && len(checkRes.Body.VSwitches.VSwitch) > 0 {
				if *checkRes.Body.VSwitches.VSwitch[0].Status == "Available" {
					return newID, nil
				}
			}
		}
		return newID, nil
	}

	return referenceVSwitch, nil
}

// resolveCompatibleVSwitch 查询可用区库存，确保所选 VSwitch 的可用区支持指定实例规格。
// 如果配置的 VSwitch 所在可用区不支持，则自动在同 VPC 下查找兼容的 VSwitch。
// 如果整个地域都没有该规格的库存，则自动尝试同族更新代的规格。
// 返回 (vSwitchID, resolvedInstanceType, error)
func (p *ECSProvider) resolveCompatibleVSwitch(cfg cloud.InstanceConfig) (string, string, error) {
	if cfg.VSwitch == "" {
		return "", "", fmt.Errorf("VSwitch is required")
	}

	// 1. 查询哪些可用区有该实例规格的库存，若无库存则尝试同族降级
	instanceType := cfg.InstanceType
	availableZones, err := p.queryAvailableZones(instanceType, cfg.SpotStrategy)
	if err != nil {
		log.Printf("[ECS] DescribeAvailableResource failed, using configured VSwitch as-is: %v", err)
		return cfg.VSwitch, instanceType, nil
	}

	// 如果首选规格无库存，尝试同族更新代的规格
	if len(availableZones) == 0 {
		fallbacks := generateFallbackTypes(instanceType)
		for _, fb := range fallbacks {
			log.Printf("[ECS] 规格 %s 无库存，尝试同族替代: %s", instanceType, fb)
			zones, err := p.queryAvailableZones(fb, cfg.SpotStrategy)
			if err != nil {
				continue
			}
			if len(zones) > 0 {
				log.Printf("[ECS] 替代规格 %s 在 %d 个可用区有库存", fb, len(zones))
				instanceType = fb
				availableZones = zones
				break
			}
		}
	}

	if len(availableZones) == 0 {
		tried := append([]string{cfg.InstanceType}, generateFallbackTypes(cfg.InstanceType)...)
		return "", "", fmt.Errorf("实例规格 %s（及同族替代 %s）在地域 %s 下均无库存，请更换规格或地域",
			cfg.InstanceType, strings.Join(tried[1:], "/"), cfg.Region)
	}

	// 2. 查询配置的 VSwitch 所在可用区
	vswReq := &ecs.DescribeVSwitchesRequest{
		RegionId:  tea.String(p.regionId),
		VSwitchId: tea.String(cfg.VSwitch),
	}
	vswRes, err := p.client.DescribeVSwitches(vswReq)
	if err != nil {
		return cfg.VSwitch, instanceType, nil
	}

	if vswRes.Body != nil && vswRes.Body.VSwitches != nil && len(vswRes.Body.VSwitches.VSwitch) > 0 {
		currentZone := ""
		currentVPC := ""
		if vswRes.Body.VSwitches.VSwitch[0].ZoneId != nil {
			currentZone = *vswRes.Body.VSwitches.VSwitch[0].ZoneId
		}
		if vswRes.Body.VSwitches.VSwitch[0].VpcId != nil {
			currentVPC = *vswRes.Body.VSwitches.VSwitch[0].VpcId
		}

		// 如果当前 VSwitch 的可用区有库存，直接使用
		if containsZone(availableZones, currentZone) {
			return cfg.VSwitch, instanceType, nil
		}

		log.Printf("[ECS] VSwitch %s 所在可用区 %s 不支持 %s，正在查找兼容的可用区...",
			cfg.VSwitch, currentZone, instanceType)

		// 3. 在同 VPC 下查找位于兼容可用区的 VSwitch
		if currentVPC != "" {
			allVswReq := &ecs.DescribeVSwitchesRequest{
				RegionId: tea.String(p.regionId),
				VpcId:    tea.String(currentVPC),
				PageSize: tea.Int32(50),
			}
			allVswRes, err := p.client.DescribeVSwitches(allVswReq)
			if err == nil && allVswRes.Body != nil && allVswRes.Body.VSwitches != nil {
				for _, vsw := range allVswRes.Body.VSwitches.VSwitch {
					zone := ""
					if vsw.ZoneId != nil {
						zone = *vsw.ZoneId
					}
					if containsZone(availableZones, zone) {
						log.Printf("[ECS] 自动切换到兼容 VSwitch %s (可用区: %s)", *vsw.VSwitchId, zone)
						return *vsw.VSwitchId, instanceType, nil
					}
				}
			}

			// 4. 同 VPC 下没有兼容 VSwitch，自动创建一个
			targetZone := availableZones[0]
			log.Printf("[ECS] 同 VPC 下无兼容 VSwitch，在可用区 %s 自动创建...", targetZone)
			createReq := &ecs.CreateVSwitchRequest{
				RegionId:    tea.String(p.regionId),
				VpcId:       tea.String(currentVPC),
				ZoneId:      tea.String(targetZone),
				CidrBlock:   tea.String(p.pickAvailableCIDR(currentVPC)),
				VSwitchName: tea.String(fmt.Sprintf("argus-auto-%s", targetZone)),
			}
			createRes, err := p.client.CreateVSwitch(createReq)
			if err != nil {
				return "", "", fmt.Errorf("自动创建兼容 VSwitch 失败 (zone=%s): %w", targetZone, err)
			}
			newVSwitchID := *createRes.Body.VSwitchId
			log.Printf("[ECS] 自动创建 VSwitch %s (zone=%s) 成功", newVSwitchID, targetZone)

			// 等待 VSwitch 可用
			for i := 0; i < 10; i++ {
				time.Sleep(2 * time.Second)
				checkReq := &ecs.DescribeVSwitchesRequest{
					RegionId:  tea.String(p.regionId),
					VSwitchId: tea.String(newVSwitchID),
				}
				checkRes, _ := p.client.DescribeVSwitches(checkReq)
				if checkRes != nil && checkRes.Body != nil && checkRes.Body.VSwitches != nil && len(checkRes.Body.VSwitches.VSwitch) > 0 {
					if *checkRes.Body.VSwitches.VSwitch[0].Status == "Available" {
						return newVSwitchID, instanceType, nil
					}
				}
			}
			return newVSwitchID, instanceType, nil
		}
	}

	return cfg.VSwitch, instanceType, nil
}

// findCompatibleImage 查找与指定实例规格兼容的公共 Ubuntu/Linux 镜像。
// 用于 ecs.e 等有严格镜像限制的经济型实例。
func (p *ECSProvider) findCompatibleImage(instanceType string) string {
	// 先尝试带 InstanceType 过滤查询
	imageId := p.searchPublicImage(instanceType)
	if imageId != "" {
		return imageId
	}
	// 不带 InstanceType 过滤再试一次（某些地域/规格不支持此过滤）
	return p.searchPublicImage("")
}

func (p *ECSProvider) searchPublicImage(instanceType string) string {
	req := &ecs.DescribeImagesRequest{
		RegionId:        tea.String(p.regionId),
		ImageOwnerAlias: tea.String("system"),
		OSType:          tea.String("linux"),
		Status:          tea.String("Available"),
		PageSize:        tea.Int32(100),
	}
	if instanceType != "" {
		req.InstanceType = tea.String(instanceType)
	}

	res, err := p.client.DescribeImages(req)
	if err != nil {
		log.Printf("[ECS] DescribeImages 查询失败 (instanceType=%s): %v", instanceType, err)
		return ""
	}
	if res.Body == nil || res.Body.Images == nil || len(res.Body.Images.Image) == 0 {
		log.Printf("[ECS] DescribeImages 无结果 (instanceType=%s, region=%s)", instanceType, p.regionId)
		return ""
	}

	log.Printf("[ECS] DescribeImages 返回 %d 个镜像 (instanceType=%s)", len(res.Body.Images.Image), instanceType)

	// 优先找 Ubuntu 22.04/20.04，其次 Alibaba Cloud Linux、Debian
	keywords := []string{"ubuntu_22", "ubuntu_20", "ubuntu", "alinux3", "alinux", "debian"}
	for _, kw := range keywords {
		for _, img := range res.Body.Images.Image {
			if img.ImageId == nil {
				continue
			}
			imgId := strings.ToLower(*img.ImageId)
			osName := ""
			if img.OSName != nil {
				osName = strings.ToLower(*img.OSName)
			}
			imgName := ""
			if img.ImageName != nil {
				imgName = strings.ToLower(*img.ImageName)
			}
			if strings.Contains(imgId, kw) || strings.Contains(osName, kw) || strings.Contains(imgName, kw) {
				log.Printf("[ECS] 找到兼容镜像: %s (name=%s, os=%s)", *img.ImageId, imgName, osName)
				return *img.ImageId
			}
		}
	}

	// 兜底：取第一个
	first := res.Body.Images.Image[0]
	if first.ImageId != nil {
		log.Printf("[ECS] 使用兜底镜像: %s", *first.ImageId)
		return *first.ImageId
	}
	return ""
}

// isFatalCloudError 判断是否为账户级致命错误（不应重试）
func isFatalCloudError(errMsg string) bool {
	fatalKeywords := []string{
		"NotEnoughBalance",             // 余额不足
		"RealNameAuthenticationError",  // 未实名认证
		"Forbidden",                    // 权限不足
		"QuotaExceeded",                // 配额超限
		"MaxSpotInstanceCountExceeded", // 抢占式实例配额超限
		"OperationDenied.RiskControl",  // 风控
	}
	for _, kw := range fatalKeywords {
		if strings.Contains(errMsg, kw) {
			return true
		}
	}
	return false
}

// generateFallbackTypes 根据原始规格生成同族更新代的替代规格列表。
// 例如 ecs.c6.large → [ecs.c7.large, ecs.c8y.large, ecs.c8i.large, ecs.c7a.large]
func generateFallbackTypes(instanceType string) []string {
	// 解析规格：ecs.<family><generation>.<size>
	// 例如 ecs.c6.large → family=c, gen=6, size=large
	parts := strings.Split(instanceType, ".")
	if len(parts) != 3 || parts[0] != "ecs" {
		return nil
	}

	familyGen := parts[1] // e.g. "c6", "g6", "r6", "c7a", "c8y"
	size := parts[2]      // e.g. "large", "xlarge", "2xlarge"

	// 提取基础系列前缀（字母部分）
	family := ""
	for _, ch := range familyGen {
		if ch >= 'a' && ch <= 'z' {
			family += string(ch)
		} else {
			break
		}
	}
	if family == "" {
		return nil
	}

	// 主流计算/通用/内存系列的代际升级路径
	// 排除 e (经济型，有镜像限制)、t (突发型，CPU 受限)、s (共享型，性能不稳定)
	upgradeMap := map[string][]string{
		"c": {"c7", "c8y", "c8i", "c7a", "c8a"}, // 计算型
		"g": {"g7", "g8y", "g8i", "g7a", "g8a"}, // 通用型
		"r": {"r7", "r8y", "r8i", "r7a", "r8a"}, // 内存型
	}

	candidates, ok := upgradeMap[family]
	if !ok {
		// 未知系列，尝试递增代际号
		gen := ""
		for _, ch := range familyGen {
			if ch >= '0' && ch <= '9' {
				gen += string(ch)
			}
		}
		if gen == "" {
			return nil
		}
		// 简单尝试 +1, +2 代
		genNum := 0
		fmt.Sscanf(gen, "%d", &genNum)
		return []string{
			fmt.Sprintf("ecs.%s%d.%s", family, genNum+1, size),
			fmt.Sprintf("ecs.%s%d.%s", family, genNum+2, size),
		}
	}

	var fallbacks []string
	for _, cand := range candidates {
		fb := fmt.Sprintf("ecs.%s.%s", cand, size)
		if fb != instanceType { // 跳过自身
			fallbacks = append(fallbacks, fb)
		}
	}
	return fallbacks
}

// queryAvailableZones 查询指定实例规格在当前地域下有库存的可用区列表
func (p *ECSProvider) queryAvailableZones(instanceType, spotStrategy string) ([]string, error) {
	destRes := "InstanceType"
	req := &ecs.DescribeAvailableResourceRequest{
		RegionId:            tea.String(p.regionId),
		DestinationResource: tea.String(destRes),
		InstanceChargeType:  tea.String("PostPaid"),
		InstanceType:        tea.String(instanceType),
		NetworkCategory:     tea.String("vpc"),
	}
	if spotStrategy != "" && spotStrategy != "NoSpot" {
		req.SpotStrategy = tea.String(spotStrategy)
	}

	res, err := p.client.DescribeAvailableResource(req)
	if err != nil {
		return nil, fmt.Errorf("DescribeAvailableResource: %w", err)
	}

	var zones []string
	if res.Body != nil && res.Body.AvailableZones != nil {
		for _, az := range res.Body.AvailableZones.AvailableZone {
			if az.ZoneId == nil {
				continue
			}
			// 接受有库存的可用区（WithStock / ClosedWithStock 均表示仍可购买）
			status := ""
			if az.StatusCategory != nil {
				status = *az.StatusCategory
			}
			if status == "WithStock" || status == "ClosedWithStock" || status == "" {
				zones = append(zones, *az.ZoneId)
			}
		}
	}
	return zones, nil
}

// pickAvailableCIDR 在 VPC 内挑选一个不冲突的 CIDR 块
func (p *ECSProvider) pickAvailableCIDR(vpcID string) string {
	// 查询已有 VSwitch 的 CIDR，避免冲突
	used := make(map[string]bool)
	vswReq := &ecs.DescribeVSwitchesRequest{
		RegionId: tea.String(p.regionId),
		VpcId:    tea.String(vpcID),
		PageSize: tea.Int32(50),
	}
	vswRes, err := p.client.DescribeVSwitches(vswReq)
	if err == nil && vswRes.Body != nil && vswRes.Body.VSwitches != nil {
		for _, vsw := range vswRes.Body.VSwitches.VSwitch {
			if vsw.CidrBlock != nil {
				used[*vsw.CidrBlock] = true
			}
		}
	}

	// 从 10.0.2.0/24 开始尝试（10.0.0.0 和 10.0.1.0 可能已被默认 VSwitch 占用）
	for i := 2; i < 255; i++ {
		cidr := fmt.Sprintf("10.0.%d.0/24", i)
		if !used[cidr] {
			return cidr
		}
	}
	return "10.0.128.0/24" // 最终兜底
}

func containsZone(zones []string, zone string) bool {
	for _, z := range zones {
		if z == zone {
			return true
		}
	}
	return false
}

// WaitReady 等待实例进入 Running 状态，支持 context 取消以防 goroutine 泄漏。
func (p *ECSProvider) WaitReady(ctx context.Context, instanceID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for instance %s: %w", instanceID, ctx.Err())
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for instance %s to be running", instanceID)
			}
			req := &ecs.DescribeInstancesRequest{
				RegionId:    tea.String(p.regionId),
				InstanceIds: tea.String(fmt.Sprintf(`["%s"]`, instanceID)),
			}
			res, err := p.client.DescribeInstances(req)
			if err != nil {
				return err
			}
			if len(res.Body.Instances.Instance) > 0 {
				status := *res.Body.Instances.Instance[0].Status
				if status == "Running" {
					return nil
				}
			}
		}
	}
}

func (p *ECSProvider) GetInstanceIP(instanceID string) (string, error) {
	req := &ecs.DescribeInstancesRequest{
		RegionId:    tea.String(p.regionId), // 修复：补充 RegionId 防止跨区域查询失败
		InstanceIds: tea.String(fmt.Sprintf(`["%s"]`, instanceID)),
	}
	res, err := p.client.DescribeInstances(req)
	if err != nil {
		return "", err
	}
	if len(res.Body.Instances.Instance) == 0 {
		return "", fmt.Errorf("instance not found")
	}

	inst := res.Body.Instances.Instance[0]
	if len(inst.PublicIpAddress.IpAddress) > 0 {
		return *inst.PublicIpAddress.IpAddress[0], nil
	}
	return "", fmt.Errorf("no public IP found")
}

func (p *ECSProvider) RebootInstance(instanceID string) error {
	req := &ecs.RebootInstanceRequest{
		InstanceId: tea.String(instanceID),
		ForceStop:  tea.Bool(true), // 强制重启，防止 Agent 假死导致 graceful shutdown 卡住
	}
	_, err := p.client.RebootInstance(req)
	if err != nil {
		return fmt.Errorf("RebootInstance error: %w", err)
	}
	return nil
}

func (p *ECSProvider) TerminateInstance(instanceID string) error {
	req := &ecs.DeleteInstancesRequest{
		RegionId:   tea.String(p.regionId),
		InstanceId: []*string{tea.String(instanceID)},
		Force:      tea.Bool(true),
	}
	_, err := p.client.DeleteInstances(req)
	return err
}

// ListInstances 带分页的实例列表查询，修复默认只返回前 10 条的问题。
func (p *ECSProvider) ListInstances(tags map[string]string) ([]*cloud.Instance, error) {
	var tagFilters []*ecs.DescribeInstancesRequestTag
	for k, v := range tags {
		tagFilters = append(tagFilters, &ecs.DescribeInstancesRequestTag{
			Key:   tea.String(k),
			Value: tea.String(v),
		})
	}

	var allInstances []*cloud.Instance
	pageNumber := int32(1)
	const pageSize = int32(100) // 阿里云单页最大值

	for {
		req := &ecs.DescribeInstancesRequest{
			RegionId:   tea.String(p.regionId),
			Tag:        tagFilters,
			PageSize:   tea.Int32(pageSize),
			PageNumber: tea.Int32(pageNumber),
		}
		res, err := p.client.DescribeInstances(req)
		if err != nil {
			return nil, err
		}

		for _, inst := range res.Body.Instances.Instance {
			ip := ""
			if len(inst.PublicIpAddress.IpAddress) > 0 {
				ip = *inst.PublicIpAddress.IpAddress[0]
			}
			allInstances = append(allInstances, &cloud.Instance{
				ID:     *inst.InstanceId,
				Status: *inst.Status,
				IP:     ip,
			})
		}

		// 检查是否还有更多页
		totalCount := *res.Body.TotalCount
		if int32(len(allInstances)) >= totalCount {
			break
		}
		pageNumber++
	}

	return allInstances, nil
}

// PriceInfo 实例价格查询结果
type PriceInfo struct {
	InstancePrice  float64 `json:"instance_price"`  // 实例小时价（元/h）
	BandwidthPrice float64 `json:"bandwidth_price"` // 带宽小时价（元/h）
	TotalHourly    float64 `json:"total_hourly"`    // 合计小时价
	Currency       string  `json:"currency"`        // 货币单位
	SpotPrice      float64 `json:"spot_price"`      // 竞价实例价格（仅 Spot 模式有值）
	SpotDiscount   float64 `json:"spot_discount"`   // 竞价折扣率 (0-100%)
	PriceUnit      string  `json:"price_unit"`      // "Hour"
}

// QueryPrice 查询实例规格的按量付费价格
func (p *ECSProvider) QueryPrice(instanceType, spotStrategy string) (*PriceInfo, error) {
	isSpot := spotStrategy != "" && spotStrategy != "NoSpot"

	// 不同地域支持的系统盘类型不同，按优先级尝试
	diskCategories := []string{"cloud_essd", "cloud_ssd", "cloud_efficiency"}
	var res *ecs.DescribePriceResponse
	var lastErr error

	for _, diskCat := range diskCategories {
		req := &ecs.DescribePriceRequest{
			RegionId:                tea.String(p.regionId),
			ResourceType:            tea.String("instance"),
			InstanceType:            tea.String(instanceType),
			PriceUnit:               tea.String("Hour"),
			InstanceNetworkType:     tea.String("vpc"),
			InternetChargeType:      tea.String("PayByTraffic"),
			InternetMaxBandwidthOut: tea.Int32(100),
		}
		req.SystemDisk = &ecs.DescribePriceRequestSystemDisk{
			Category: tea.String(diskCat),
		}

		// 竞价实例价格查询：必须同时传 SpotStrategy 和 SpotDuration
		if isSpot {
			req.SpotStrategy = tea.String(spotStrategy)
			req.SpotDuration = tea.Int32(0) // 0 = 无保护期，最便宜
		}

		var err error
		res, err = p.client.DescribePrice(req)
		if err != nil {
			if strings.Contains(err.Error(), "SystemDiskCategory") {
				lastErr = err
				continue // 尝试下一种盘类型
			}
			return nil, fmt.Errorf("DescribePrice: %w", err)
		}
		break // 成功
	}

	if res == nil {
		return nil, fmt.Errorf("DescribePrice: 所有磁盘类型均不支持: %w", lastErr)
	}

	info := &PriceInfo{
		Currency:  "CNY",
		PriceUnit: "Hour",
	}

	if res.Body != nil && res.Body.PriceInfo != nil && res.Body.PriceInfo.Price != nil {
		price := res.Body.PriceInfo.Price
		if price.TradePrice != nil {
			info.TotalHourly = float64(*price.TradePrice)
		}
		if price.OriginalPrice != nil {
			info.InstancePrice = float64(*price.OriginalPrice)
		}
		if price.DiscountPrice != nil {
			discount := float64(*price.DiscountPrice)
			if info.InstancePrice > 0 {
				info.SpotDiscount = (discount / info.InstancePrice) * 100
			}
		}
		if price.Currency != nil {
			info.Currency = *price.Currency
		}
	}

	// 竞价模式：查竞价历史均价作为最准确的实时价格
	if isSpot {
		spotReq := &ecs.DescribeSpotPriceHistoryRequest{
			RegionId:     tea.String(p.regionId),
			InstanceType: tea.String(instanceType),
			NetworkType:  tea.String("vpc"),
		}
		spotRes, err := p.client.DescribeSpotPriceHistory(spotReq)
		if err == nil && spotRes.Body != nil && spotRes.Body.SpotPrices != nil && len(spotRes.Body.SpotPrices.SpotPriceType) > 0 {
			// 取最新一条竞价价格
			latest := spotRes.Body.SpotPrices.SpotPriceType[len(spotRes.Body.SpotPrices.SpotPriceType)-1]
			if latest.SpotPrice != nil {
				info.SpotPrice = float64(*latest.SpotPrice)
			}
			if latest.OriginPrice != nil && info.SpotPrice > 0 {
				info.SpotDiscount = (1 - info.SpotPrice/float64(*latest.OriginPrice)) * 100
				info.InstancePrice = float64(*latest.OriginPrice)
			}
		}

		// 核心：竞价价格覆盖 TotalHourly，保证前端显示正确
		if info.SpotPrice > 0 {
			info.TotalHourly = info.SpotPrice
		}
	}

	return info, nil
}
