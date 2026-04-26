package db

import (
	"time"

	"gorm.io/gorm"
)

// ============================================================================
// 云资源编排数据模型
//
// 三表设计:
//   - CloudAccount       — 云厂商凭证 (AK/SK 加密存储)
//   - CloudScalingPolicy — 自动伸缩策略 (阈值、冷却期、竞价配置)
//   - CloudInstance       — 实例生命周期追踪
// ============================================================================

// CloudAccount 云厂商凭证存储
type CloudAccount struct {
	ID                   string `gorm:"primaryKey"`
	TenantID             string `gorm:"default:'default';index"`
	Name                 string // 凭证名称，如 "阿里云-华东2"
	Provider             string `gorm:"index"` // aliyun, aws, tencent
	AccessKeyID          string // AES-256-GCM 加密后的 AccessKey ID
	AccessKeySecret      string // AES-256-GCM 加密后的 AccessKey Secret
	Region               string // 默认区域，如 cn-shanghai
	DefaultImageID       string // 默认镜像 ID (预装 Agent 环境)
	DefaultInstanceType  string // 默认实例规格，如 ecs.c6.large
	DefaultSecurityGroup string // 默认安全组 ID
	DefaultVSwitch       string // 默认虚拟交换机 ID
	Status               string `gorm:"default:'active';index"` // active, disabled
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// CloudScalingPolicy 自动伸缩策略
type CloudScalingPolicy struct {
	ID              string `gorm:"primaryKey"`
	TenantID        string `gorm:"default:'default';index"`
	CloudAccountID  string `gorm:"index"` // 关联 CloudAccount
	Name            string // 策略名称
	Enabled         bool   `gorm:"default:false;index"` // 是否启用
	MinInstances    int    `gorm:"default:0"`            // 最小实例数
	MaxInstances    int    `gorm:"default:5"`            // 最大实例数（硬上限，防止计费失控）
	ScaleUpThreshold  int  `gorm:"default:50"`           // 队列积压超过此值时触发扩容
	ScaleDownThreshold int `gorm:"default:3"`            // 空闲节点数超过此值时触发缩容
	CooldownSeconds   int  `gorm:"default:300"`          // 扩缩容冷却时间（秒），防止震荡
	InstanceTTLMinutes int `gorm:"default:120"`          // 实例最大存活时间（分钟）
	SpotStrategy      string `gorm:"default:'NoSpot'"`   // NoSpot / SpotAsPriceGo / SpotWithPriceLimit
	MaxSpotPrice      float64                            // 竞价最高价（SpotWithPriceLimit 时有效）
	UserDataTemplate  string `gorm:"type:text"`          // Cloud-Init 模板（可使用 Go template 变量）
	LastScaleAction   *time.Time                         // 最近一次伸缩操作时间（用于冷却期判定）
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// CloudInstance 实例生命周期追踪
type CloudInstance struct {
	ID                 string `gorm:"primaryKey"`
	TenantID           string `gorm:"default:'default';index"`
	CloudAccountID     string `gorm:"index"`                    // 关联 CloudAccount
	PolicyID           string `gorm:"index"`                    // 关联 CloudScalingPolicy
	ProviderInstanceID string `gorm:"index"`                    // 云厂商侧实例 ID (如 i-xxx)
	AgentID            string `gorm:"index"`                    // 对应的 Argus Agent ID
	IP                 string                                   // 实例公网/私网 IP
	Region             string                                   // 实例所在区域
	Status             string `gorm:"default:'Provisioning';index"` // 状态机见下方
	Spot               bool   `gorm:"default:false"`            // 是否竞价实例
	RebootCount        int    `gorm:"default:0"`                // 累计重启次数（用于梯度容错策略）
	ErrorMessage       string `gorm:"type:text"`                // 创建/运行错误信息
	LaunchedAt         *time.Time                               // 实例创建时间
	ReadyAt            *time.Time                               // 实例就绪时间 (Agent 注册成功)
	TerminatedAt       *time.Time                               // 实例销毁时间
	CreatedAt          time.Time
	UpdatedAt          time.Time
	DeletedAt          gorm.DeletedAt `gorm:"index"`            // 软删除
}

// CloudInstance 状态机:
//   Provisioning  → 正在创建实例
//   WaitingReady  → 实例已创建，等待 Agent 注册
//   Running       → Agent 已注册并正常运行
//   Rebooting     → 正在重启中（Agent 断线后触发的 OS 级重启）
//   Terminating   → 正在销毁
//   Terminated    → 已销毁
//   Error         → 创建或运行出错

// CloudInstanceStatus 常量
const (
	CloudStatusProvisioning = "Provisioning"
	CloudStatusWaitingReady = "WaitingReady"
	CloudStatusRunning      = "Running"
	CloudStatusRebooting    = "Rebooting"
	CloudStatusTerminating  = "Terminating"
	CloudStatusTerminated   = "Terminated"
	CloudStatusError        = "Error"
)
