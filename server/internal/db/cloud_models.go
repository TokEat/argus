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
	ID                   string    `gorm:"primaryKey" json:"id"`
	TenantID             string    `gorm:"default:'default';index" json:"tenant_id"`
	OwnerUserID          string    `gorm:"index" json:"owner_user_id"`           // 创建/归属用户 ID
	Name                 string    `json:"name"`                                 // 凭证名称，如 "阿里云-华东2"
	Provider             string    `gorm:"index" json:"provider"`                // aliyun, aws, tencent
	AccessKeyID          string    `json:"access_key_id"`                        // AES-256-GCM 加密后的 AccessKey ID
	AccessKeySecret      string    `json:"-"`                                    // AES-256-GCM 加密后的 AccessKey Secret
	Region               string    `json:"region"`                               // 默认区域，如 cn-shanghai
	DefaultImageID       string    `json:"default_image_id"`                     // 默认镜像 ID (预装 Agent 环境)
	DefaultInstanceType  string    `json:"default_instance_type"`                // 默认实例规格，如 ecs.c6.large
	DefaultSecurityGroup string    `json:"default_security_group"`               // 默认安全组 ID
	DefaultVSwitch       string    `json:"default_v_switch"`                     // 默认虚拟交换机 ID
	OSSBucket            string    `json:"oss_bucket"`                           // OSS 存储桶名称（用于 Agent 二进制分发）
	OSSEndpoint          string    `json:"oss_endpoint"`                         // OSS 内网 Endpoint（如 oss-cn-shanghai-internal.aliyuncs.com）
	Status               string    `gorm:"default:'active';index" json:"status"` // active, disabled
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// CloudAccountBinding 表示某个用户可使用某个云账号凭证。
type CloudAccountBinding struct {
	ID             uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	TenantID       string    `gorm:"default:'default';index:idx_cloud_account_binding_unique,unique;index" json:"tenant_id"`
	CloudAccountID string    `gorm:"index:idx_cloud_account_binding_unique,unique;index" json:"cloud_account_id"`
	UserID         string    `gorm:"index:idx_cloud_account_binding_unique,unique;index" json:"user_id"`
	AccessType     string    `gorm:"default:'bound'" json:"access_type"` // owner, bound
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// CloudScalingPolicy 自动伸缩策略
type CloudScalingPolicy struct {
	ID                 string     `gorm:"primaryKey" json:"id"`
	TenantID           string     `gorm:"default:'default';index" json:"tenant_id"`
	CloudAccountID     string     `gorm:"index" json:"cloud_account_id"`                // 关联 CloudAccount
	Name               string     `json:"name"`                                         // 策略名称
	Enabled            bool       `gorm:"default:false;index" json:"enabled"`           // 是否启用
	MinInstances       int        `gorm:"default:0" json:"min_instances"`               // 最小实例数
	MaxInstances       int        `gorm:"default:5" json:"max_instances"`               // 最大实例数（硬上限，防止计费失控）
	ScaleUpThreshold   int        `gorm:"default:50" json:"scale_up_threshold"`         // 队列积压超过此值时触发扩容
	ScaleDownThreshold int        `gorm:"default:3" json:"scale_down_threshold"`        // 空闲节点数超过此值时触发缩容
	CooldownSeconds    int        `gorm:"default:300" json:"cooldown_seconds"`          // 扩缩容冷却时间（秒），防止震荡
	InstanceTTLMinutes int        `gorm:"default:120" json:"instance_ttl_minutes"`      // 实例最大存活时间（分钟）
	SpotStrategy       string     `gorm:"default:'SpotAsPriceGo'" json:"spot_strategy"` // NoSpot / SpotAsPriceGo / SpotWithPriceLimit
	MaxSpotPrice       float64    `json:"max_spot_price"`                               // 竞价最高价（SpotWithPriceLimit 时有效）
	SpotDurationHours  int        `gorm:"default:1" json:"spot_duration_hours"`         // 抢占式保留时长（小时，0-6；0=无保护期，随时可回收）
	UserDataTemplate   string     `gorm:"type:text" json:"user_data_template"`          // Cloud-Init 模板（可使用 Go template 变量）
	LastScaleAction    *time.Time `json:"last_scale_action"`                            // 最近一次伸缩操作时间（用于冷却期判定）
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// CloudInstance 实例生命周期追踪
type CloudInstance struct {
	ID                 string         `gorm:"primaryKey" json:"id"`
	TenantID           string         `gorm:"default:'default';index" json:"tenant_id"`
	CloudAccountID     string         `gorm:"index" json:"cloud_account_id"`              // 关联 CloudAccount
	PolicyID           string         `gorm:"index" json:"policy_id"`                     // 关联 CloudScalingPolicy
	ProviderInstanceID string         `gorm:"index" json:"provider_instance_id"`          // 云厂商侧实例 ID (如 i-xxx)
	AgentID            string         `gorm:"index" json:"agent_id"`                      // 对应的 Argus Agent ID
	IP                 string         `json:"ip"`                                         // 实例公网/私网 IP
	Region             string         `json:"region"`                                     // 实例所在区域
	Status             string         `gorm:"default:'Provisioning';index" json:"status"` // 状态机见下方
	Spot               bool           `gorm:"default:false" json:"spot"`                  // 是否竞价实例
	RebootCount        int            `gorm:"default:0" json:"reboot_count"`              // 累计重启次数（用于梯度容错策略）
	ErrorMessage       string         `gorm:"type:text" json:"error_message"`             // 创建/运行错误信息
	LaunchedAt         *time.Time     `json:"launched_at"`                                // 实例创建时间
	ReadyAt            *time.Time     `json:"ready_at"`                                   // 实例就绪时间 (Agent 注册成功)
	TerminatedAt       *time.Time     `json:"terminated_at"`                              // 实例销毁时间
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"-"` // 软删除
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
