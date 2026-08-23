package subdomainpassive

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRealCollectorCollects 对真实公共数据源执行一次完整收集（源查询 + 后缀
// 过滤 + 泛解析基线 + DNS 解析验证）。默认跳过，避免常规 CI 依赖外网与
// 第三方源可用性；需要真实冒烟时显式指定域名：
//
//	ARGUS_REAL_PASSIVE_TEST=chng.com.cn,impc.com.cn \
//	  go test ./internal/subdomainpassive -run TestRealCollectorCollects -v -count=1
func TestRealCollectorCollects(t *testing.T) {
	raw := strings.TrimSpace(os.Getenv("ARGUS_REAL_PASSIVE_TEST"))
	if raw == "" {
		t.Skip("ARGUS_REAL_PASSIVE_TEST not set; real-network collection smoke disabled")
	}
	domains := strings.Split(raw, ",")
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		t.Run(domain, func(t *testing.T) {
			collector := NewCollector()
			started := time.Now()
			result, err := collector.Collect(context.Background(), domain)
			if err != nil {
				t.Fatalf("real collection failed for %s: %v", domain, err)
			}
			t.Logf("domain=%s validated_subdomains=%d sources=%v elapsed=%s",
				domain, len(result.Subdomains), result.Sources, time.Since(started).Round(time.Millisecond))
			preview := result.Subdomains
			if len(preview) > 10 {
				preview = preview[:10]
			}
			t.Logf("sample: %s", strings.Join(preview, ", "))
			if len(result.Subdomains) == 0 {
				t.Fatalf("expected at least one validated subdomain for %s", domain)
			}
			for _, host := range result.Subdomains {
				if !strings.HasSuffix(host, "."+domain) {
					t.Fatalf("suffix invariant violated: %s", host)
				}
			}
		})
	}
}
