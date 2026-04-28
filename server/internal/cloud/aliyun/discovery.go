package aliyun

import (
	"fmt"

	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	"github.com/alibabacloud-go/tea/tea"
)

// DiscoveryResult 资源发现结果
type DiscoveryResult struct {
	// 安全组
	SecurityGroups []ResourceItem `json:"security_groups"`
	// 交换机
	VSwitches []ResourceItem `json:"v_switches"`
	// 镜像（公共+自定义）
	Images []ResourceItem `json:"images"`
	// 推荐的实例规格
	InstanceTypes []InstanceTypeItem `json:"instance_types"`
	// VPC
	VPCs []ResourceItem `json:"vpcs"`
}

// ResourceItem 通用资源条目
type ResourceItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc,omitempty"`
}

// InstanceTypeItem 实例规格条目
type InstanceTypeItem struct {
	ID     string  `json:"id"`
	CPU    int     `json:"cpu"`
	Memory float64 `json:"memory_gb"`
	Family string  `json:"family"`
}

// DiscoverResources 根据 AK/SK 自动发现该地域下可用的云资源
func (p *ECSProvider) DiscoverResources() (interface{}, error) {
	if p.regionId == "" {
		return nil, fmt.Errorf("资源发现需要指定地域 (Region)，请先选择地域后再执行")
	}
	result := &DiscoveryResult{}


	// 1. 查询安全组
	sgReq := &ecs.DescribeSecurityGroupsRequest{
		RegionId: tea.String(p.regionId),
		PageSize: tea.Int32(50),
	}
	sgRes, err := p.client.DescribeSecurityGroups(sgReq)
	if err == nil && sgRes.Body != nil && sgRes.Body.SecurityGroups != nil {
		for _, sg := range sgRes.Body.SecurityGroups.SecurityGroup {
			name := ""
			if sg.SecurityGroupName != nil {
				name = *sg.SecurityGroupName
			}
			desc := ""
			if sg.Description != nil {
				desc = *sg.Description
			}
			vpcID := ""
			if sg.VpcId != nil {
				vpcID = *sg.VpcId
			}
			result.SecurityGroups = append(result.SecurityGroups, ResourceItem{
				ID:   *sg.SecurityGroupId,
				Name: name,
				Desc: fmt.Sprintf("VPC: %s | %s", vpcID, desc),
			})
		}
	}

	// 2. 查询 VPC
	vpcReq := &ecs.DescribeVpcsRequest{
		RegionId: tea.String(p.regionId),
		PageSize: tea.Int32(50),
	}
	vpcRes, err := p.client.DescribeVpcs(vpcReq)
	if err == nil && vpcRes.Body != nil && vpcRes.Body.Vpcs != nil {
		for _, vpc := range vpcRes.Body.Vpcs.Vpc {
			name := ""
			if vpc.VpcName != nil {
				name = *vpc.VpcName
			}
			cidr := ""
			if vpc.CidrBlock != nil {
				cidr = *vpc.CidrBlock
			}
			result.VPCs = append(result.VPCs, ResourceItem{
				ID:   *vpc.VpcId,
				Name: name,
				Desc: cidr,
			})
		}
	}

	// 3. 查询交换机
	vswReq := &ecs.DescribeVSwitchesRequest{
		RegionId: tea.String(p.regionId),
		PageSize: tea.Int32(50),
	}
	vswRes, err := p.client.DescribeVSwitches(vswReq)
	if err == nil && vswRes.Body != nil && vswRes.Body.VSwitches != nil {
		for _, vsw := range vswRes.Body.VSwitches.VSwitch {
			name := ""
			if vsw.VSwitchName != nil {
				name = *vsw.VSwitchName
			}
			zone := ""
			if vsw.ZoneId != nil {
				zone = *vsw.ZoneId
			}
			cidr := ""
			if vsw.CidrBlock != nil {
				cidr = *vsw.CidrBlock
			}
			result.VSwitches = append(result.VSwitches, ResourceItem{
				ID:   *vsw.VSwitchId,
				Name: name,
				Desc: fmt.Sprintf("可用区: %s | CIDR: %s", zone, cidr),
			})
		}
	}

	// 4. 查询公共镜像（Linux、Ubuntu/CentOS 优先）
	for _, osType := range []string{"ubuntu", "centos", "aliyun"} {
		imgReq := &ecs.DescribeImagesRequest{
			RegionId:        tea.String(p.regionId),
			ImageOwnerAlias: tea.String("system"),
			OSType:          tea.String("linux"),
			ImageName:       tea.String(osType + "*"),
			PageSize:        tea.Int32(10),
			Status:          tea.String("Available"),
		}
		imgRes, err := p.client.DescribeImages(imgReq)
		if err == nil && imgRes.Body != nil && imgRes.Body.Images != nil {
			for _, img := range imgRes.Body.Images.Image {
				name := ""
				if img.ImageName != nil {
					name = *img.ImageName
				}
				desc := ""
				if img.OSNameEn != nil {
					desc = *img.OSNameEn
				}
				result.Images = append(result.Images, ResourceItem{
					ID:   *img.ImageId,
					Name: name,
					Desc: desc,
				})
			}
		}
	}

	// 5. 查询推荐实例规格（计算型 c 系列优先）
	itReq := &ecs.DescribeInstanceTypesRequest{
		InstanceTypeFamily: tea.String("ecs.c6"),
	}
	itRes, err := p.client.DescribeInstanceTypes(itReq)
	if err == nil && itRes.Body != nil && itRes.Body.InstanceTypes != nil {
		for _, it := range itRes.Body.InstanceTypes.InstanceType {
			cpu := int32(0)
			if it.CpuCoreCount != nil {
				cpu = *it.CpuCoreCount
			}
			mem := float32(0)
			if it.MemorySize != nil {
				mem = *it.MemorySize
			}
			// 只显示 2~16 核的规格，过滤超大机型
			if cpu >= 2 && cpu <= 16 {
				result.InstanceTypes = append(result.InstanceTypes, InstanceTypeItem{
					ID:     *it.InstanceTypeId,
					CPU:    int(cpu),
					Memory: float64(mem),
					Family: "ecs.c6",
				})
			}
		}
	}

	// 补充 g6 (通用型) 系列
	itReq2 := &ecs.DescribeInstanceTypesRequest{
		InstanceTypeFamily: tea.String("ecs.g6"),
	}
	itRes2, err := p.client.DescribeInstanceTypes(itReq2)
	if err == nil && itRes2.Body != nil && itRes2.Body.InstanceTypes != nil {
		for _, it := range itRes2.Body.InstanceTypes.InstanceType {
			cpu := int32(0)
			if it.CpuCoreCount != nil {
				cpu = *it.CpuCoreCount
			}
			mem := float32(0)
			if it.MemorySize != nil {
				mem = *it.MemorySize
			}
			if cpu >= 2 && cpu <= 16 {
				result.InstanceTypes = append(result.InstanceTypes, InstanceTypeItem{
					ID:     *it.InstanceTypeId,
					CPU:    int(cpu),
					Memory: float64(mem),
					Family: "ecs.g6",
				})
			}
		}
	}

	return result, nil
}
