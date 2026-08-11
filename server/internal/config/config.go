package config

import "time"

// Config 定义控制面的运行配置。
// 当前阶段先沉淀配置结构，后续再逐步替换 cmd 中的散落 flag 解析。
type Config struct {
	App      AppConfig
	HTTP     HTTPConfig
	GRPC     GRPCConfig
	Database DatabaseConfig
	Redis    RedisConfig
	Rule     RuleConfig
	Agent    AgentConfig
}

type AppConfig struct {
	Name        string
	Environment string
}

type HTTPConfig struct {
	Address string
}

type GRPCConfig struct {
	Port int
}

type DatabaseConfig struct {
	DSN string
}

type RedisConfig struct {
	Address  string
	Password string
	DB       int
}

type RuleConfig struct {
	ActiveBundle string
}

type AgentConfig struct {
	HeartbeatTimeout time.Duration
	SweepInterval    time.Duration
}

func Default() Config {
	return Config{
		App: AppConfig{
			Name:        "argus-server",
			Environment: "local",
		},
		HTTP: HTTPConfig{
			Address: ":8085",
		},
		GRPC: GRPCConfig{
			Port: 50051,
		},
		Database: DatabaseConfig{
			DSN: "",
		},
		Redis: RedisConfig{
			Address: "",
			DB:      0,
		},
		Rule: RuleConfig{
			ActiveBundle: "bootstrap",
		},
		Agent: AgentConfig{
			HeartbeatTimeout: 60 * time.Second,
			SweepInterval:    30 * time.Second,
		},
	}
}
