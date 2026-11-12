package agent

import (
	"fmt"
	"strings"

	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/internal/engine"
	"github.com/TokEat/argus/scanner/structs"
)

func mirrorAgentConsoleOutput(msg engine.OutputMessage) {
	mirrorAgentConsoleOutputForMode(msg, "")
}

func mirrorAgentConsoleOutputForMode(msg engine.OutputMessage, executionMode string) {
	// Credential findings contain the raw successful secret until the Server
	// seals them. They may travel only on the authenticated TLS result stream,
	// never through the Agent console or persistent log tee.
	if !shouldMirrorAgentOutputForMode(msg.Type, executionMode) {
		return
	}

	line := ddout.Render(toDDOutOutputMessage(msg))
	if line != "" {
		fmt.Println(line)
	}
}

func shouldMirrorAgentOutputForMode(messageType, executionMode string) bool {
	if strings.EqualFold(strings.TrimSpace(executionMode), "credential_validation") {
		return false
	}
	return shouldMirrorAgentOutput(messageType)
}

func shouldMirrorAgentOutput(messageType string) bool {
	switch messageType {
	case "Finger", "Active-Finger", "GoPoc", "Domain-Bind":
		return true
	default:
		return false
	}
}

func toDDOutOutputMessage(msg engine.OutputMessage) ddout.OutputMessage {
	return ddout.OutputMessage{
		Type:     msg.Type,
		IP:       msg.IP,
		IPs:      append([]string(nil), msg.IPs...),
		Port:     msg.Port,
		Protocol: msg.Protocol,
		Web: ddout.WebInfo{
			Status: msg.Web.Status,
			Title:  msg.Web.Title,
		},
		Finger: append([]string(nil), msg.Finger...),
		Domain: msg.Domain,
		GoPoc: ddout.GoPocsResultType{
			PocName:     msg.GoPoc.PocName,
			Security:    msg.GoPoc.Security,
			Description: msg.GoPoc.Description,
			Target:      msg.GoPoc.Target,
			InfoLeft:    msg.GoPoc.InfoLeft,
			InfoRight:   msg.GoPoc.InfoRight,
			ShowMsg:     msg.GoPoc.ShowMsg,
			Exchanges:   append([]structs.GoPocExchange(nil), msg.GoPoc.Exchanges...),
		},
		URI:           msg.URI,
		City:          msg.City,
		AdditionalMsg: msg.AdditionalMsg,
		Show:          msg.Show,
		Nuclei:        msg.Nuclei,
	}
}
