package cloud

import (
	"fmt"
	"sync"

	"github.com/user/dddd-server/internal/db"
)

// ============================================================================
// Provider 注册表 — 使用注册模式打破循环导入
//
// 各云厂商 Provider（如 aliyun）在 init() 中调用 RegisterProviderFactory
// 注册自己的工厂函数，cloud 包不直接导入任何 Provider 子包。
// ============================================================================

// ProviderFactory 创建 CloudProvider 实例的工厂函数
type ProviderFactory func(akID, akSecret, region string) (CloudProvider, error)

var (
	providerFactories = make(map[string]ProviderFactory)
	factoryMu         sync.RWMutex
)

// RegisterProviderFactory 注册一个云厂商的 Provider 工厂函数。
// 在各 Provider 子包的 init() 中调用。
func RegisterProviderFactory(providerName string, factory ProviderFactory) {
	factoryMu.Lock()
	defer factoryMu.Unlock()
	providerFactories[providerName] = factory
}

// NewProviderFromAccount 根据 CloudAccount 配置创建对应的 CloudProvider。
// 凭证在此函数中解密。
func NewProviderFromAccount(account *db.CloudAccount) (CloudProvider, error) {
	// 解密凭证
	akID, err := DecryptSecret(account.AccessKeyID)
	if err != nil {
		return nil, fmt.Errorf("decrypt access_key_id: %w", err)
	}
	akSecret, err := DecryptSecret(account.AccessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("decrypt access_key_secret: %w", err)
	}

	factoryMu.RLock()
	factory, ok := providerFactories[account.Provider]
	factoryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unsupported cloud provider: %s (registered: %v)", account.Provider, registeredProviders())
	}

	return factory(akID, akSecret, account.Region)
}

// registeredProviders 返回已注册的 Provider 名称列表
func registeredProviders() []string {
	factoryMu.RLock()
	defer factoryMu.RUnlock()
	names := make([]string, 0, len(providerFactories))
	for name := range providerFactories {
		names = append(names, name)
	}
	return names
}
