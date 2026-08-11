package httpx

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var newProbeRunner = runner.New

func RemoveDuplicateElement(input []string) []string {
	temp := map[string]struct{}{}
	var result []string
	for _, item := range input {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func sanitizeTimeout(timeout int) int {
	if timeout <= 0 {
		return 10
	}
	return timeout
}

func sanitizeThreads(threads int) int {
	if threads <= 0 {
		return 50
	}
	return threads
}

// runEnumerationWithGuard 为 httpx 枚举增加总耗时保护，避免单阶段无限卡住。
func runEnumerationWithGuard(httpxRunner *runner.Runner, stage string, timeoutSec int, targetCount int) bool {
	if httpxRunner == nil {
		return true
	}
	timeoutSec = sanitizeTimeout(timeoutSec)
	if targetCount <= 0 {
		targetCount = 1
	}
	// 总预算：每个目标 timeout*(retries+1) 秒，再留固定余量；最低 30s。
	budget := time.Duration(timeoutSec*(targetCount+1)+15) * time.Second
	minBudget := 30 * time.Second
	if budget < minBudget {
		budget = minBudget
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		httpxRunner.RunEnumeration()
	}()

	select {
	case <-done:
		return true
	case <-time.After(budget):
		gologger.Error().Msgf("[%s] httpx enumeration exceeded %s (targets=%d, timeout=%ds), force closing runner",
			stage, budget, targetCount, timeoutSec)
		httpxRunner.Close()
		return false
	}
}

func CallHTTPx(urls []string, callBack func(resp runner.Result), proxy string, threads int, timeout int) {
	session := NewProbeSession(context.Background(), timeout)
	defer session.Close()
	session.CallHTTPx(urls, callBack, proxy, threads)
}

func CallHTTPxFollowHostRedirects(urls []string, callBack func(resp runner.Result), proxy string, threads int, timeout int) {
	session := NewProbeSession(context.Background(), timeout)
	defer session.Close()
	session.CallHTTPxFollowHostRedirects(urls, callBack, proxy, threads)
}

func (s *ProbeSession) CallHTTPx(urls []string, callBack func(resp runner.Result), proxy string, threads int) {
	s.callHTTPx(urls, callBack, proxy, threads, false)
}

func (s *ProbeSession) CallHTTPxFollowHostRedirects(urls []string, callBack func(resp runner.Result), proxy string, threads int) {
	s.callHTTPx(urls, callBack, proxy, threads, true)
}

func (s *ProbeSession) callHTTPx(urls []string, callBack func(resp runner.Result), proxy string, threads int, followHostRedirects bool) {
	gologger.Info().Msg("获取Web响应中")

	timeout := int(s.timeout / time.Second)
	if timeout <= 0 {
		timeout = sanitizeTimeout(timeout)
	}
	threads = sanitizeThreads(threads)

	nextUrls := s.reserveInputs(urls)
	if len(nextUrls) == 0 {
		return
	}

	gologger.AuditLogger("响应探测目标: %s", strings.Join(nextUrls, ","))

	times := 0
	for len(nextUrls) > 0 && times < 3 {
		nextUrls = filterActiveTargets(s, nextUrls)
		if len(nextUrls) == 0 {
			break
		}
		gologger.Info().Msgf("[HTTPProbe] pass=%d targets=%d threads=%d timeout=%ds", times+1, len(nextUrls), threads, timeout)
		maxRedirects := 3
		if followHostRedirects {
			maxRedirects = 8
		}

		t0 := time.Now()
		options := runner.Options{
			Methods:                   "GET",
			InputTargetHost:           nextUrls,
			Favicon:                   true,
			Hashes:                    "md5",
			OutputServerHeader:        true,
			TLSProbe:                  false,
			TLSGrab:                   true,
			MaxResponseBodySizeToRead: 1048576,
			FollowHostRedirects:       followHostRedirects,
			MaxRedirects:              maxRedirects,
			ExtractTitle:              true,
			Timeout:                   timeout,
			Retries:                   1,
			HTTPProxy:                 proxy,
			NoFallbackScheme:          true,
			RandomAgent:               true,
			Threads:                   threads,
			TargetContext:             s.TargetContext,
		}

		if err := options.ValidateOptions(); err != nil {
			gologger.Error().Msgf("params error: %v", err)
		}

		gologger.Info().Msgf("[HTTPProbe] 创建httpx runner...")
		httpxRunner, err := newProbeRunner(&options)
		if err != nil {
			gologger.Error().Msgf("[HTTPProbe] runner.New 失败: %v", err)
			break
		}
		// Build the Runner before claiming visits so a construction failure does
		// not permanently suppress a later attempt in the same scan. Runner keeps
		// the options pointer and consumes inputs only in RunEnumeration.
		nextUrls = s.reserveUnvisitedURLs(nextUrls)
		if len(nextUrls) == 0 {
			httpxRunner.Close()
			break
		}
		options.InputTargetHost = nextUrls
		gologger.Info().Msgf("[HTTPProbe] runner创建耗时: %v", time.Since(t0))
		httpxRunner.CallBack = s.wrapCallback(callBack)

		gologger.Info().Msgf("[HTTPProbe] 开始RunEnumeration...")
		// Request cancellation is supplied through TargetContext. Run synchronously
		// so Runner resources are not closed concurrently with callbacks.
		httpxRunner.RunEnumeration()
		gologger.Info().Msgf("[HTTPProbe] RunEnumeration完成, 耗时: %v", time.Since(t0))
		httpxRunner.Close()
		nextUrls = s.registerNextCheckTargets(httpxRunner.NextCheckTargets)
		times += 1

	}
	gologger.AuditTimeLogger("响应探测结束")

}

func filterActiveTargets(session *ProbeSession, urls []string) []string {
	active := make([]string, 0, len(urls))
	for _, raw := range urls {
		if session.isActive(raw) {
			active = append(active, raw)
		} else {
			session.markExpiredFollowUp(raw)
		}
	}
	return active
}

func init() {
	if os.Getenv("DEBUG") != "" {
		errorutil.ShowStackTrace = true
	}
}

func DirBrute(urls []string, callBack func(resp runner.Result), proxy string, threads int, timeout int) {
	urls = RemoveDuplicateElement(urls)
	if len(urls) == 0 {
		return
	}
	timeout = sanitizeTimeout(timeout)
	threads = sanitizeThreads(threads)

	options := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           urls,
		Favicon:                   true,
		Hashes:                    "md5",
		OutputServerHeader:        true,
		TLSProbe:                  false, // 同主探测一样关闭 TLS 资产发现
		TLSGrab:                   true,  // 保留 TLS 证书抓取
		MaxResponseBodySizeToRead: 1048576,
		FollowHostRedirects:       false,
		MaxRedirects:              3,
		ExtractTitle:              true,
		Timeout:                   timeout,
		IsBrute:                   true,
		Retries:                   1,
		HTTPProxy:                 proxy,
		NoFallbackScheme:          true,
		RandomAgent:               true,
		Threads:                   threads,
	}

	if err := options.ValidateOptions(); err != nil {
		gologger.Error().Msgf("params error")
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		gologger.Error().Msgf("runner.New(&options) error")
	}
	httpxRunner.CallBack = callBack

	_ = runEnumerationWithGuard(httpxRunner, "dir_brute", timeout, len(urls))
	httpxRunner.Close()
}
