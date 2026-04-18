package cloud

import "time"

// InstanceConfig 定义了创建云实例所需的通用配置
type InstanceConfig struct {
	Region        string            // 区域
	InstanceType  string            // 实例规格 (如 ecs.c6.large)
	ImageID       string            // 系统镜像ID（需预装好基础环境）
	SecurityGroup string            // 安全组ID
	VSwitch       string            // 虚拟交换机ID
	UserData      string            // cloud-init 启动脚本（用于拉起 agent）
	Tags          map[string]string // 实例标签
	MaxPrice      float64           // 竞价实例最高容忍价格（0为按量付费）
	SpotStrategy  string            // SpotAsPriceGo 或 SpotWithPriceLimit
}

// Instance 描述一个正在运行中的云节点
type Instance struct {
	ID        string    // 实例唯一ID
	IP        string    // 实例公网或私网IP
	Status    string    // 实例状态 (Pending, Starting, Running, Terminated)
	CreatedAt time.Time // 创建时间
}

// CloudProvider 云服务编排的抽象接口
type CloudProvider interface {
	// CreateInstance 根据配置申请创建云实例（可以是竞价实例或按量付费）
	CreateInstance(cfg InstanceConfig) (*Instance, error)

	// WaitReady 等待实例状态变更为可运行（如操作系统就绪，网络分配完成）
	WaitReady(instanceID string, timeout time.Duration) error

	// GetInstanceIP 获取实例的公网/私网通信IP
	GetInstanceIP(instanceID string) (string, error)

	// TerminateInstance 销毁实例释放资源
	TerminateInstance(instanceID string) error

	// ListInstances 根据特定的 tag 获取当前正在运行的实例列表 (用于异常状态监控与孤儿实例回收)
	ListInstances(tags map[string]string) ([]*Instance, error)
}
