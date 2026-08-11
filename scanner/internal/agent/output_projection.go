package agent

import (
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/internal/engine"
	"github.com/P0lar1ght/argus/scanner/structs"
)

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
