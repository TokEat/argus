package aliyun

import (
	"fmt"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	ecs "github.com/alibabacloud-go/ecs-20140526/v4/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/user/dddd-server/internal/cloud"
)

func init() {
	cloud.RegisterProviderFactory("aliyun", func(akID, akSecret, region string) (cloud.CloudProvider, error) {
		return NewECSProvider(akID, akSecret, region)
	})
}

type ECSProvider struct {
	client   *ecs.Client
	regionId string
}

func NewECSProvider(accessKeyId, accessKeySecret, regionId string) (*ECSProvider, error) {
	config := &openapi.Config{
		AccessKeyId:     tea.String(accessKeyId),
		AccessKeySecret: tea.String(accessKeySecret),
		Endpoint:        tea.String(fmt.Sprintf("ecs.%s.aliyuncs.com", regionId)),
	}
	client, err := ecs.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &ECSProvider{client: client, regionId: regionId}, nil
}

func (p *ECSProvider) CreateInstance(cfg cloud.InstanceConfig) (*cloud.Instance, error) {
	req := &ecs.RunInstancesRequest{
		RegionId:                tea.String(cfg.Region),
		ImageId:                 tea.String(cfg.ImageID),
		InstanceType:            tea.String(cfg.InstanceType),
		SecurityGroupId:         tea.String(cfg.SecurityGroup),
		VSwitchId:               tea.String(cfg.VSwitch),
		UserData:                tea.String(cfg.UserData), // Base64 encoded cloud-init script
		InstanceChargeType:      tea.String("PostPaid"),   // 按量付费
		InternetChargeType:      tea.String("PayByTraffic"),
		InternetMaxBandwidthOut: tea.Int32(100),
		Amount:                  tea.Int32(1),
	}

	// 注入 Argus 管理标签
	var tagList []*ecs.RunInstancesRequestTag
	for k, v := range cfg.Tags {
		tagList = append(tagList, &ecs.RunInstancesRequestTag{
			Key:   tea.String(k),
			Value: tea.String(v),
		})
	}
	if len(tagList) > 0 {
		req.Tag = tagList
	}

	// 竞价实例支持
	if cfg.MaxPrice > 0 {
		req.SpotStrategy = tea.String(cfg.SpotStrategy)
		req.SpotPriceLimit = tea.Float32(float32(cfg.MaxPrice))
	} else if cfg.SpotStrategy != "" && cfg.SpotStrategy != "NoSpot" {
		req.SpotStrategy = tea.String(cfg.SpotStrategy)
	} else {
		req.SpotStrategy = tea.String("NoSpot")
	}

	res, err := p.client.RunInstances(req)
	if err != nil {
		return nil, fmt.Errorf("RunInstances error: %w", err)
	}

	if len(res.Body.InstanceIdSets.InstanceIdSet) == 0 {
		return nil, fmt.Errorf("no instance ID returned")
	}

	instanceID := *res.Body.InstanceIdSets.InstanceIdSet[0]

	// 这里不立刻获取 IP，需要 WaitReady 后再获取
	return &cloud.Instance{
		ID:        instanceID,
		Status:    "Pending",
		CreatedAt: time.Now(),
	}, nil
}

func (p *ECSProvider) WaitReady(instanceID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		req := &ecs.DescribeInstancesRequest{
			RegionId:    tea.String(p.regionId),
			InstanceIds: tea.String(fmt.Sprintf("[\"%s\"]", instanceID)),
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
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("timeout waiting for instance %s to be running", instanceID)
}

func (p *ECSProvider) GetInstanceIP(instanceID string) (string, error) {
	req := &ecs.DescribeInstancesRequest{
		InstanceIds: tea.String(fmt.Sprintf("[\"%s\"]", instanceID)),
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
		InstanceId: []*string{tea.String(instanceID)},
		Force:      tea.Bool(true),
	}
	_, err := p.client.DeleteInstances(req)
	return err
}

func (p *ECSProvider) ListInstances(tags map[string]string) ([]*cloud.Instance, error) {
	var tagFilters []*ecs.DescribeInstancesRequestTag
	for k, v := range tags {
		tagFilters = append(tagFilters, &ecs.DescribeInstancesRequestTag{
			Key:   tea.String(k),
			Value: tea.String(v),
		})
	}

	req := &ecs.DescribeInstancesRequest{
		Tag: tagFilters,
	}
	res, err := p.client.DescribeInstances(req)
	if err != nil {
		return nil, err
	}

	var instances []*cloud.Instance
	for _, inst := range res.Body.Instances.Instance {
		ip := ""
		if len(inst.PublicIpAddress.IpAddress) > 0 {
			ip = *inst.PublicIpAddress.IpAddress[0]
		}
		instances = append(instances, &cloud.Instance{
			ID:     *inst.InstanceId,
			Status: *inst.Status,
			IP:     ip,
		})
	}
	return instances, nil
}
