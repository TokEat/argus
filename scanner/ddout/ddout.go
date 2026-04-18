// Package ddout 统一输出引擎。
// 所有扫描结果通过 FormatOutput 经由可替换的 Sink 函数输出。
// CLI 模式下 Sink 写文件/终端；Agent 模式下 Sink 走 gRPC 回传。
package ddout

import (
	"dddd/scanner/structs"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// GoPocsResultType 复用 structs 中的类型。
type GoPocsResultType = structs.GoPocsResultType

// WebInfo Web 页面信息。
type WebInfo struct {
	Status string `json:"status,omitempty"`
	Title  string `json:"title,omitempty"`
}

// OutputMessage 统一输出消息格式。
type OutputMessage struct {
	Type          string           `json:"type,omitempty"`
	IP            string           `json:"ip,omitempty"`
	IPs           []string         `json:"ips,omitempty"`
	Port          string           `json:"port,omitempty"`
	Protocol      string           `json:"protocol,omitempty"`
	Web           WebInfo          `json:"web,omitempty"`
	Finger        []string         `json:"finger,omitempty"`
	Domain        string           `json:"domain,omitempty"`
	GoPoc         GoPocsResultType `json:"go_poc,omitempty"`
	URI           string           `json:"uri,omitempty"`
	City          string           `json:"city,omitempty"`
	AdditionalMsg string           `json:"am,omitempty"`
	Show          string           `json:"-"`
	Nuclei        string           `json:"nuclei,omitempty"`
}

// OutputType 当前输出格式 ("text" 或 "json")。
var OutputType string = "text"

// OutputFileName 输出文件名。
var OutputFileName string

// outputSink 可替换的输出处理函数。
// 默认为 nil，使用 defaultFormatOutput。
var (
	outputSink func(msg OutputMessage)
	sinkMu     sync.Mutex
)

// SetOutputSink 设置自定义的输出处理器，返回先前的处理器。
func SetOutputSink(sink func(msg OutputMessage)) func(msg OutputMessage) {
	sinkMu.Lock()
	defer sinkMu.Unlock()
	prev := outputSink
	outputSink = sink
	return prev
}

// FormatOutput 格式化并输出一条扫描结果。
func FormatOutput(msg OutputMessage) {
	sinkMu.Lock()
	sink := outputSink
	sinkMu.Unlock()

	if sink != nil {
		sink(msg)
		return
	}

	// 默认输出逻辑
	defaultFormatOutput(msg)
}

// defaultFormatOutput 默认的输出实现（写终端 + 写文件）。
func defaultFormatOutput(msg OutputMessage) {
	line := formatLine(msg)
	if line == "" {
		return
	}

	gologger.Silent().Msgf("%s", line)

	if OutputFileName != "" {
		appendToFile(OutputFileName, line)
	}
}

// formatLine 根据消息类型和输出格式生成一行输出。
func formatLine(msg OutputMessage) string {
	if OutputType == "json" {
		b, _ := json.Marshal(msg)
		return string(b)
	}

	// text 模式
	switch msg.Type {
	case "IPAlive":
		if msg.AdditionalMsg != "" {
			return fmt.Sprintf("[Alive] %s (%s)", msg.IP, msg.AdditionalMsg)
		}
		return fmt.Sprintf("[Alive] %s", msg.IP)
	case "PortScan":
		return fmt.Sprintf("[Port] %s:%s", msg.IP, msg.Port)
	case "Protocol":
		return fmt.Sprintf("[Protocol] %s:%s %s", msg.IP, msg.Port, msg.Protocol)
	case "Web":
		parts := []string{fmt.Sprintf("[Web] %s", msg.URI)}
		if msg.Web.Status != "" {
			parts = append(parts, msg.Web.Status)
		}
		if msg.Web.Title != "" {
			parts = append(parts, msg.Web.Title)
		}
		if len(msg.Finger) > 0 {
			parts = append(parts, "["+strings.Join(msg.Finger, ",")+"]")
		}
		return strings.Join(parts, " ")
	case "Finger":
		return fmt.Sprintf("[Finger] %s [%s]", msg.URI, strings.Join(msg.Finger, ","))
	case "Nuclei":
		return fmt.Sprintf("[Vuln] %s", msg.Nuclei)
	case "GoPoc":
		return fmt.Sprintf("[Poc] %s %s %s", msg.GoPoc.Target, msg.GoPoc.PocName, msg.GoPoc.Description)
	case "Domain":
		return fmt.Sprintf("[Domain] %s -> %s", msg.Domain, strings.Join(msg.IPs, ","))
	default:
		if msg.Show != "" {
			return msg.Show
		}
		return ""
	}
}

func appendToFile(filename, line string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, line)
}
