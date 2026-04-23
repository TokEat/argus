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

// WebInfo is an alias for backward compatibility (optional but good).
type WebInfo = structs.WebInfo

// OutputMessage is an alias.
type OutputMessage = structs.OutputMessage

// GoPocsResultType is an alias.
type GoPocsResultType = structs.GoPocsResultType

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
	case "Active-Finger":
		line := fmt.Sprintf("[Active-Finger] %s [%s]", msg.URI, strings.Join(msg.Finger, ","))
		if msg.AdditionalMsg != "" {
			line += " " + msg.AdditionalMsg
		}
		return line
	case "Domain-Bind":
		if msg.Web.Status != "" {
			return fmt.Sprintf("[Domain-Bind] [%s] %s", msg.Web.Status, msg.URI)
		}
		return fmt.Sprintf("[Domain-Bind] %s", msg.URI)
	case "Nuclei":
		if msg.Show != "" {
			return fmt.Sprintf("[Nuclei] %s", msg.Show)
		}
		return fmt.Sprintf("[Nuclei] %s", msg.Nuclei)
	case "GoPoc":
		detail := strings.TrimSpace(msg.GoPoc.ShowMsg)
		if detail == "" {
			detail = strings.TrimSpace(fmt.Sprintf("%s %s %s", msg.GoPoc.Target, msg.GoPoc.PocName, msg.GoPoc.Description))
		}
		if msg.GoPoc.Security != "" {
			return fmt.Sprintf("[%s] %s", msg.GoPoc.Security, detail)
		}
		return fmt.Sprintf("[GoPoc] %s", detail)
	case "Domain":
		return fmt.Sprintf("[Domain] %s -> %s", msg.Domain, strings.Join(msg.IPs, ","))
	default:
		if msg.Show != "" {
			return msg.Show
		}
		return ""
	}
}

// Render returns the text-mode line for a message without writing it.
func Render(msg OutputMessage) string {
	return formatLine(msg)
}

func appendToFile(filename, line string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, line)
}
