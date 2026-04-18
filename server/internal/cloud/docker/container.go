package docker

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/user/dddd-server/internal/cloud"
)

// DockerProvider 包装本地 docker cli 提供一个沙盒测试用的云供给层
type DockerProvider struct {
	network string
}

func NewDockerProvider(network string) *DockerProvider {
	if network == "" {
		network = "host"
	}
	return &DockerProvider{network: network}
}

func (p *DockerProvider) CreateInstance(cfg cloud.InstanceConfig) (*cloud.Instance, error) {
	// Instance ID 使用当前纳秒生成一个伪ID
	instanceID := fmt.Sprintf("docker-agent-%d", time.Now().UnixNano())

	// 解析UserData用于环境变量
	// 实际环境应该是打在镜像里通过环境变量传入
	serverAddr := "127.0.0.1:50051"
	if strings.Contains(cfg.UserData, "SERVER_ADDR=") {
		// 极简解析
		parts := strings.Split(cfg.UserData, "SERVER_ADDR=")
		if len(parts) > 1 {
			serverAddr = strings.Split(parts[1], " ")[0]
			serverAddr = strings.Trim(serverAddr, "\"\n")
		}
	}

	// 执行: docker run -d --name {instanceID} --network {network} {ImageId} /usr/local/bin/dddd-agent --server ... --id ...
	cmd := exec.Command("docker", "run", "-d",
		"--name", instanceID,
		"--network", p.network,
		cfg.ImageID,
		"/usr/local/bin/dddd-agent",
		"--server", serverAddr,
		"--id", instanceID,
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker run error: %v, stderr: %s", err, stderr.String())
	}

	return &cloud.Instance{
		ID:        instanceID,
		Status:    "Pending", // docker 其实是秒启动的
		CreatedAt: time.Now(),
	}, nil
}

func (p *DockerProvider) WaitReady(instanceID string, timeout time.Duration) error {
	// Docker 几乎是秒开
	return nil
}

func (p *DockerProvider) GetInstanceIP(instanceID string) (string, error) {
	// 取出容器内部 IP
	out, err := exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", instanceID).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (p *DockerProvider) TerminateInstance(instanceID string) error {
	_ = exec.Command("docker", "stop", instanceID).Run()
	return exec.Command("docker", "rm", "-f", instanceID).Run()
}

func (p *DockerProvider) ListInstances(tags map[string]string) ([]*cloud.Instance, error) {
	// 测试环境可以简单列出特定的前缀
	out, err := exec.Command("docker", "ps", "-q", "-f", "name=docker-agent-").Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var instances []*cloud.Instance
	for _, id := range lines {
		if id == "" {
			continue
		}
		instances = append(instances, &cloud.Instance{
			ID:     id,
			Status: "Running",
		})
	}

	return instances, nil
}
