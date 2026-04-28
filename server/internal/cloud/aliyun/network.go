package aliyun

import (
	"fmt"
	"time"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	"github.com/alibabacloud-go/tea/tea"
)

// AutoCreateOSS 自动在当前地域下创建 OSS 存储桶
func (p *ECSProvider) AutoCreateOSS(accountID string) (bucketName string, endpoint string, err error) {
	endpoint = fmt.Sprintf("oss-%s.aliyuncs.com", p.regionId)
	client, err := oss.New(endpoint, p.akID, p.akSecret)
	if err != nil {
		return "", "", fmt.Errorf("create OSS client: %w", err)
	}

	suffix := fmt.Sprintf("%x", time.Now().UnixNano())[:8]
	bucketName = fmt.Sprintf("argus-agent-%s-%s", p.regionId, suffix)

	err = client.CreateBucket(bucketName)
	if err != nil {
		return "", "", fmt.Errorf("create bucket %s: %w", bucketName, err)
	}

	err = client.SetBucketACL(bucketName, oss.ACLPrivate)
	if err != nil {
		return bucketName, endpoint, fmt.Errorf("set bucket ACL: %w", err)
	}

	return bucketName, endpoint, nil
}

// AutoCreateNetwork 自动在当前地域下创建 VPC、VSwitch 和安全组
func (p *ECSProvider) AutoCreateNetwork() (sgID string, vswID string, err error) {
	// 1. 查询是否有现成的 VPC
	var vpcId string
	vpcReq := &ecs.DescribeVpcsRequest{
		RegionId: tea.String(p.regionId),
		PageSize: tea.Int32(10),
	}
	vpcRes, err := p.client.DescribeVpcs(vpcReq)
	if err == nil && vpcRes.Body != nil && vpcRes.Body.Vpcs != nil && len(vpcRes.Body.Vpcs.Vpc) > 0 {
		vpcId = *vpcRes.Body.Vpcs.Vpc[0].VpcId
	}

	// 2. 如果没有 VPC，创建一个
	if vpcId == "" {
		createVpcReq := &ecs.CreateVpcRequest{
			RegionId:  tea.String(p.regionId),
			CidrBlock: tea.String("10.0.0.0/8"),
			VpcName:   tea.String("argus-auto-vpc"),
		}
		createVpcRes, err := p.client.CreateVpc(createVpcReq)
		if err != nil {
			return "", "", fmt.Errorf("创建 VPC 失败: %v", err)
		}
		vpcId = *createVpcRes.Body.VpcId

		// 等待 VPC 可用
		for i := 0; i < 10; i++ {
			time.Sleep(2 * time.Second)
			checkReq := &ecs.DescribeVpcsRequest{
				RegionId: tea.String(p.regionId),
				VpcId:    tea.String(vpcId),
			}
			checkRes, _ := p.client.DescribeVpcs(checkReq)
			if checkRes != nil && checkRes.Body != nil && checkRes.Body.Vpcs != nil && len(checkRes.Body.Vpcs.Vpc) > 0 {
				if *checkRes.Body.Vpcs.Vpc[0].Status == "Available" {
					break
				}
			}
		}
	}

	// 3. 确保交换机
	vswReq := &ecs.DescribeVSwitchesRequest{
		RegionId: tea.String(p.regionId),
		VpcId:    tea.String(vpcId),
		PageSize: tea.Int32(10),
	}
	vswRes, err := p.client.DescribeVSwitches(vswReq)
	if err == nil && vswRes.Body != nil && vswRes.Body.VSwitches != nil && len(vswRes.Body.VSwitches.VSwitch) > 0 {
		vswID = *vswRes.Body.VSwitches.VSwitch[0].VSwitchId
	} else {
		// 需要一个 Zone ID
		zoneReq := &ecs.DescribeZonesRequest{
			RegionId: tea.String(p.regionId),
		}
		zoneRes, err := p.client.DescribeZones(zoneReq)
		if err != nil || zoneRes.Body == nil || zoneRes.Body.Zones == nil || len(zoneRes.Body.Zones.Zone) == 0 {
			return "", "", fmt.Errorf("获取可用区失败: %v", err)
		}
		zoneId := *zoneRes.Body.Zones.Zone[0].ZoneId

		createVswReq := &ecs.CreateVSwitchRequest{
			RegionId:    tea.String(p.regionId),
			VpcId:       tea.String(vpcId),
			ZoneId:      tea.String(zoneId),
			CidrBlock:   tea.String("10.0.1.0/24"),
			VSwitchName: tea.String("argus-auto-vsw"),
		}
		createVswRes, err := p.client.CreateVSwitch(createVswReq)
		if err != nil {
			return "", "", fmt.Errorf("创建交换机失败: %v", err)
		}
		vswID = *createVswRes.Body.VSwitchId

		// 等待交换机可用
		for i := 0; i < 10; i++ {
			time.Sleep(2 * time.Second)
			checkReq := &ecs.DescribeVSwitchesRequest{
				RegionId:  tea.String(p.regionId),
				VSwitchId: tea.String(vswID),
			}
			checkRes, _ := p.client.DescribeVSwitches(checkReq)
			if checkRes != nil && checkRes.Body != nil && checkRes.Body.VSwitches != nil && len(checkRes.Body.VSwitches.VSwitch) > 0 {
				if *checkRes.Body.VSwitches.VSwitch[0].Status == "Available" {
					break
				}
			}
		}
	}

	// 4. 确保安全组
	sgReq := &ecs.DescribeSecurityGroupsRequest{
		RegionId: tea.String(p.regionId),
		VpcId:    tea.String(vpcId),
		PageSize: tea.Int32(10),
	}
	sgRes, err := p.client.DescribeSecurityGroups(sgReq)
	if err == nil && sgRes.Body != nil && sgRes.Body.SecurityGroups != nil && len(sgRes.Body.SecurityGroups.SecurityGroup) > 0 {
		sgID = *sgRes.Body.SecurityGroups.SecurityGroup[0].SecurityGroupId
	} else {
		createSgReq := &ecs.CreateSecurityGroupRequest{
			RegionId:          tea.String(p.regionId),
			VpcId:             tea.String(vpcId),
			SecurityGroupName: tea.String("argus-auto-sg"),
			SecurityGroupType: tea.String("normal"),
		}
		createSgRes, err := p.client.CreateSecurityGroup(createSgReq)
		if err != nil {
			return "", "", fmt.Errorf("创建安全组失败: %v", err)
		}
		sgID = *createSgRes.Body.SecurityGroupId
		// 默认创建的安全组通常已经包含出方向 allow all，不需要特别加规则
	}

	return sgID, vswID, nil
}
