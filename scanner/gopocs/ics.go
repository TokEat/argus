package gopocs

import (
	"encoding/hex"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"github.com/projectdiscovery/gologger"
	"time"
)

func DNP3Scan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// DNP3 Link Layer Read request
	probe, _ := hex.DecodeString("056405060100000055c4")
	conn.Write(probe)
	gologger.AuditTimeLogger("[Go] [DNP3] Dumped TCP request for %s\n\n%s\n", realhost, hex.Dump(probe))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return err
	}
	gologger.AuditTimeLogger("[Go] [DNP3] Dumped TCP response for %s\n\n%s\n", realhost, hex.Dump(buf[:n]))
	if buf[0] != 0x05 || buf[1] != 0x64 {
		return nil
	}

	result := fmt.Sprintf("DNP3://%s Device Detected", realhost)
	emitICS(info, "DNP3-Detect", realhost, result, "DNP3协议设备")
	return nil
}

func S7Scan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// COTP Connection Request
	cotpCR, _ := hex.DecodeString("0300001611e00000000100c0010ac1020100c2020102")
	conn.Write(cotpCR)
	gologger.AuditTimeLogger("[Go] [S7] Dumped COTP CR for %s\n\n%s\n", realhost, hex.Dump(cotpCR))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return err
	}
	if buf[0] != 0x03 || buf[1] != 0x00 {
		return nil
	}

	// S7 Setup Communication
	s7Setup, _ := hex.DecodeString("0300001902f08032010000000000080000f0000001000101e0")
	conn.Write(s7Setup)
	gologger.AuditTimeLogger("[Go] [S7] Dumped S7 Setup for %s\n\n%s\n", realhost, hex.Dump(s7Setup))

	n, err = conn.Read(buf)
	if err != nil || n < 12 {
		return err
	}
	gologger.AuditTimeLogger("[Go] [S7] Dumped S7 response for %s\n\n%s\n", realhost, hex.Dump(buf[:n]))

	result := fmt.Sprintf("S7://%s PLC Detected", realhost)
	emitICS(info, "S7-Detect", realhost, result, "Siemens S7 PLC")
	return nil
}

func EtherNetIPScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// EtherNet/IP ListIdentity
	probe, _ := hex.DecodeString("630000000000000000000000000000000000000000000000")
	conn.Write(probe)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return err
	}
	if buf[0] != 0x63 {
		return nil
	}

	result := fmt.Sprintf("EtherNet/IP://%s CIP Device Detected", realhost)
	emitICS(info, "EtherNetIP-Detect", realhost, result, "EtherNet/IP CIP设备")
	return nil
}

func ATGScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// ATG I20100 inventory command
	probe := []byte("\x01I20100\n")
	conn.Write(probe)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return err
	}
	resp := string(buf[:n])
	if len(resp) < 3 {
		return nil
	}

	result := fmt.Sprintf("ATG://%s Tank Gauge Detected", realhost)
	emitICS(info, "ATG-Detect", realhost, result, "自动液位计(ATG)")
	return nil
}

func MELSECScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// MELSEC-Q binary read
	probe, _ := hex.DecodeString("5700000011000000000000ffff0300001c001008000000000000000000000104010001000000")
	conn.Write(probe)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return err
	}
	if buf[0] != 0xd7 && buf[0] != 0x57 {
		return nil
	}

	result := fmt.Sprintf("MELSEC://%s PLC Detected", realhost)
	emitICS(info, "MELSEC-Detect", realhost, result, "三菱MELSEC-Q PLC")
	return nil
}

func FINSScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// FINS/TCP node address request
	probe, _ := hex.DecodeString("46494e530000000c00000000000000000000000000")
	conn.Write(probe)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return err
	}
	if string(buf[:4]) != "FINS" {
		return nil
	}

	result := fmt.Sprintf("FINS://%s Omron PLC Detected", realhost)
	emitICS(info, "FINS-Detect", realhost, result, "欧姆龙FINS PLC")
	return nil
}

func CrimsonScan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	probe, _ := hex.DecodeString("00040116")
	conn.Write(probe)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return err
	}

	result := fmt.Sprintf("Crimson://%s Red Lion Device Detected", realhost)
	emitICS(info, "Crimson-Detect", realhost, result, "Red Lion Crimson v3")
	return nil
}

func IEC104Scan(info *structs.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, 6*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// STARTDT act U-frame
	probe, _ := hex.DecodeString("680407000000")
	conn.Write(probe)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 6 {
		return err
	}
	if buf[0] != 0x68 {
		return nil
	}

	result := fmt.Sprintf("IEC104://%s RTU/SCADA Detected", realhost)
	emitICS(info, "IEC104-Detect", realhost, result, "IEC-60870-5-104 RTU/SCADA")
	return nil
}

func emitICS(info *structs.HostInfo, pocName, target, showMsg, desc string) {
	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     pocName,
			Security:    "INFO",
			Target:      target,
			Description: desc,
			ShowMsg:     showMsg,
		},
	})
	writeResult(info, structs.GoPocsResultType{
		PocName:     pocName,
		Security:    "INFO",
		Target:      target,
		Description: desc,
	})
}
