package aliyun

import (
	"errors"
	"fmt"

	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	"github.com/alibabacloud-go/tea/tea"
)

// createSetupVSwitch stays in the selected VPC and retries only an explicit
// disabled-zone rejection. Other errors may have an ambiguous creation result.
func (p *ECSProvider) createSetupVSwitch(vpcID string) (string, error) {
	response, err := p.client.DescribeZones(&ecs.DescribeZonesRequest{
		RegionId: tea.String(p.regionId), Verbose: tea.Bool(true),
	})
	if err != nil {
		return "", fmt.Errorf("获取可用区失败: %w", err)
	}
	var zones []string
	if response != nil && response.Body != nil && response.Body.Zones != nil {
		zones = setupVSwitchZones(response.Body.Zones.Zone)
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("地域 %s 没有支持创建交换机的可用区", p.regionId)
	}
	var lastErr error
	for _, zoneID := range zones {
		created, err := p.client.CreateVSwitch(&ecs.CreateVSwitchRequest{
			RegionId: tea.String(p.regionId), VpcId: tea.String(vpcID), ZoneId: tea.String(zoneID),
			CidrBlock: tea.String("10.0.1.0/24"), VSwitchName: tea.String("argus-auto-vsw"),
		})
		if err != nil {
			lastErr = fmt.Errorf("创建交换机失败 (zone=%s): %w", zoneID, err)
			var sdkErr *tea.SDKError
			if errors.As(err, &sdkErr) && tea.StringValue(sdkErr.Code) == "OperationDenied.ZoneIsDisabled" {
				continue
			}
			return "", lastErr
		}
		if created == nil || created.Body == nil || tea.StringValue(created.Body.VSwitchId) == "" {
			return "", fmt.Errorf("创建交换机未返回交换机 ID (zone=%s)，请先检查云端资源再重试", zoneID)
		}
		return tea.StringValue(created.Body.VSwitchId), nil
	}
	return "", fmt.Errorf("地域 %s 的候选可用区均已停用: %w", p.regionId, lastErr)
}

func setupVSwitchZones(zones []*ecs.DescribeZonesResponseBodyZonesZone) []string {
	var supported, unknown []string
	seen := make(map[string]bool)
	for _, zone := range zones {
		if zone == nil || tea.StringValue(zone.ZoneId) == "" {
			continue
		}
		id := tea.StringValue(zone.ZoneId)
		if seen[id] {
			continue
		}
		seen[id] = true
		if zone.AvailableResourceCreation == nil {
			// Older responses can omit capabilities; use them after advertised zones.
			unknown = append(unknown, id)
			continue
		}
		for _, resource := range zone.AvailableResourceCreation.ResourceTypes {
			if tea.StringValue(resource) == "VSwitch" {
				supported = append(supported, id)
				break
			}
		}
	}
	return append(supported, unknown...)
}
