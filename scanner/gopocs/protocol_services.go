package gopocs

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/structs"
	"github.com/TokEat/argus/scanner/utils"
)

const readonlyValidationTimeout = 6 * time.Second

func RocketMQBrokerScan(info *structs.HostInfo) error {
	return rocketMQReadonlyScan(info, "RocketMQ-Broker-Unauthorized", "RocketMQ Broker只读管理接口未授权访问（关联CVE-2023-33246风险，未执行配置写入）", 26, "RocketMQ Broker GET_BROKER_CONFIG")
}

func RocketMQNameServerScan(info *structs.HostInfo) error {
	return rocketMQReadonlyScan(info, "RocketMQ-NameServer-Unauthorized", "RocketMQ NameServer只读路由接口未授权访问（关联CVE-2023-37582风险，未执行配置写入）", 106, "RocketMQ NameServer GET_BROKER_CLUSTER_INFO")
}

func RabbitMQAMQPScan(info *structs.HostInfo) error {
	realhost := gopocTarget(info)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, readonlyValidationTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(readonlyValidationTimeout))

	header := []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}
	written, err := conn.Write(header)
	if err != nil {
		return err
	}
	startFrame, err := readAMQPFrame(conn)
	if err != nil {
		return err
	}
	class, method, ok := amqpMethod(startFrame)
	if !ok || class != 10 || method != 10 {
		return nil
	}

	startOK := amqpStartOKFrame()
	startOKWritten, err := conn.Write(startOK)
	if err != nil {
		return err
	}
	authFrame, err := readAMQPFrame(conn)
	if err != nil {
		return err
	}
	class, method, ok = amqpMethod(authFrame)
	if !ok || class != 10 || method != 30 {
		return nil
	}

	emitGoPoc(info, "RabbitMQ-AMQP-Anonymous", "HIGH", realhost, "", "RabbitMQ AMQP允许空凭据进入连接调优阶段；CVE-2023-34050仅作为应用端反序列化关联风险提示", fmt.Sprintf("RabbitMQ-AMQP://%s Empty Credentials Accepted", realhost),
		binaryGoPocWriteExchange("AMQP protocol header", header, written, startFrame),
		binaryGoPocWriteExchange("AMQP empty PLAIN Start-Ok", startOK, startOKWritten, authFrame))
	return nil
}

func EPMDScan(info *structs.HostInfo) error {
	realhost := gopocTarget(info)
	probe := []byte{0x00, 0x01, 0x6e}
	response, written, err := tcpWriteRead(realhost, probe, 4096)
	if err != nil || !looksLikeEPMDResponse(response) {
		return err
	}
	nodes := epmdNodeSummary(response)
	emitGoPoc(info, "EPMD-Node-Exposure", "MEDIUM", realhost, nodes, "EPMD节点枚举暴露；CouchDB CVE-2022-24706仅作为组合风险提示，未验证CVE", fmt.Sprintf("EPMD://%s Node Names Exposed", realhost),
		binaryGoPocWriteExchange("EPMD names request", probe, written, response))
	return nil
}

func CassandraScan(info *structs.HostInfo) error {
	realhost := gopocTarget(info)
	request := cassandraStartupRequest()
	response, written, err := tcpWriteRead(realhost, request, 4096)
	if err != nil || !cassandraReadyResponse(response) {
		return err
	}
	emitGoPoc(info, "Cassandra-Unauthorized", "HIGH", realhost, "", "Cassandra CQL STARTUP无认证进入READY阶段；未执行查询或写入", fmt.Sprintf("Cassandra://%s Anonymous CQL READY", realhost),
		binaryGoPocWriteExchange("Cassandra CQL STARTUP", request, written, response))
	return nil
}

func ClickHouseScan(info *structs.HostInfo) error {
	realhost := gopocTarget(info)
	request := clickHouseDefaultUserHello()
	response, written, err := tcpWriteRead(realhost, request, 4096)
	if err != nil || !clickHouseServerHello(response) {
		return err
	}
	emitGoPoc(info, "ClickHouse-Unauthorized", "MEDIUM", realhost, "", "ClickHouse native协议default用户空密码握手通过；未执行查询或写入", fmt.Sprintf("ClickHouse://%s Default User Empty Password Accepted", realhost),
		binaryGoPocWriteExchange("ClickHouse native default-user hello", request, written, response))
	return nil
}

func rocketMQReadonlyScan(info *structs.HostInfo, pocName, description string, code int, label string) error {
	realhost := gopocTarget(info)
	request := rocketMQRequest(code)
	conn, err := utils.WrapperTcpWithTimeout("tcp", realhost, readonlyValidationTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(readonlyValidationTimeout))
	written, err := conn.Write(request)
	if err != nil {
		return err
	}
	response, err := readRocketMQFrame(conn)
	if err != nil || !rocketMQSuccess(response) {
		return err
	}
	infoLeft := rocketMQInfo(response)
	emitGoPoc(info, pocName, "HIGH", realhost, infoLeft, description, fmt.Sprintf("RocketMQ://%s Readonly Admin Request Accepted", realhost),
		binaryGoPocWriteExchange(label, request, written, response))
	return nil
}

func gopocTarget(info *structs.HostInfo) string {
	if info == nil {
		return ""
	}
	return fmt.Sprintf("%s:%v", info.Host, info.Ports)
}

func tcpWriteRead(address string, request []byte, size int) ([]byte, int, error) {
	conn, err := utils.WrapperTcpWithTimeout("tcp", address, readonlyValidationTimeout)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(readonlyValidationTimeout))
	written := 0
	if len(request) > 0 {
		written, err = conn.Write(request)
		if err != nil {
			return nil, written, err
		}
	}
	if size <= 0 {
		size = 4096
	}
	buf := make([]byte, size)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], written, nil
	}
	return nil, written, err
}

func emitGoPoc(info *structs.HostInfo, pocName, security, target, infoLeft, description, showMsg string, exchanges ...structs.GoPocExchange) {
	emittedExchanges := append([]structs.GoPocExchange(nil), exchanges...)
	storedExchanges := append([]structs.GoPocExchange(nil), exchanges...)
	result := structs.GoPocsResultType{
		PocName:     pocName,
		Security:    security,
		Target:      target,
		InfoLeft:    infoLeft,
		Exchanges:   emittedExchanges,
		Description: description,
		ShowMsg:     showMsg,
	}
	if info != nil && info.Emit != nil {
		info.Emit(ddout.OutputMessage{Type: "GoPoc", GoPoc: result})
	}
	result.Exchanges = storedExchanges
	writeResult(info, result)
}

func rocketMQRequest(code int) []byte {
	header := map[string]interface{}{
		"code":     code,
		"language": "JAVA",
		"version":  395,
		"opaque":   code,
		"flag":     0,
	}
	encoded, _ := json.Marshal(header)
	frameLen := 4 + len(encoded)
	out := make([]byte, 4+frameLen)
	binary.BigEndian.PutUint32(out[0:4], uint32(frameLen))
	binary.BigEndian.PutUint32(out[4:8], uint32(len(encoded)))
	copy(out[8:], encoded)
	return out
}

func readRocketMQFrame(reader io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint32(header))
	if size <= 4 || size > 1<<20 {
		return nil, fmt.Errorf("invalid RocketMQ frame size %d", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

func rocketMQHeader(response []byte) ([]byte, bool) {
	if len(response) < 12 {
		return nil, false
	}
	size := int(binary.BigEndian.Uint32(response[0:4]))
	if size <= 4 || size > len(response)-4 {
		return nil, false
	}
	headerLen := int(binary.BigEndian.Uint32(response[4:8]) & 0x00ffffff)
	if headerLen <= 0 || headerLen > size-4 || 8+headerLen > len(response) {
		return nil, false
	}
	return response[8 : 8+headerLen], true
}

func rocketMQSuccess(response []byte) bool {
	header, ok := rocketMQHeader(response)
	if !ok {
		return false
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(header, &decoded); err == nil {
		if code, ok := decoded["code"].(float64); ok && code == 0 {
			return true
		}
	}
	compact := bytes.ReplaceAll(header, []byte(" "), nil)
	return bytes.Contains(compact, []byte(`"code":0`))
}

func rocketMQInfo(response []byte) string {
	header, ok := rocketMQHeader(response)
	if !ok {
		return ""
	}
	bodyStart := 8 + len(header)
	if bodyStart >= len(response) {
		return ""
	}
	body := strings.TrimSpace(string(response[bodyStart:]))
	if body == "" {
		return ""
	}
	if len(body) > 96 {
		body = body[:96]
	}
	return body
}

func readAMQPFrame(reader io.Reader) ([]byte, error) {
	header := make([]byte, 7)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint32(header[3:7]))
	if size < 0 || size > 1<<20 {
		return nil, fmt.Errorf("invalid AMQP frame size %d", size)
	}
	body := make([]byte, size+1)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

func amqpMethod(frame []byte) (uint16, uint16, bool) {
	if len(frame) < 12 || frame[0] != 1 {
		return 0, 0, false
	}
	size := int(binary.BigEndian.Uint32(frame[3:7]))
	if size < 4 || 7+size >= len(frame) {
		return 0, 0, false
	}
	payload := frame[7 : 7+size]
	return binary.BigEndian.Uint16(payload[0:2]), binary.BigEndian.Uint16(payload[2:4]), true
}

func amqpStartOKFrame() []byte {
	response := []byte{0x00, 0x00, 0x00}
	payload := []byte{0x00, 0x0a, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x05, 'P', 'L', 'A', 'I', 'N'}
	longstrLen := make([]byte, 4)
	binary.BigEndian.PutUint32(longstrLen, uint32(len(response)))
	payload = append(payload, longstrLen...)
	payload = append(payload, response...)
	payload = append(payload, 0x05, 'e', 'n', '_', 'U', 'S')
	return amqpMethodFrame(payload)
}

func amqpMethodFrame(payload []byte) []byte {
	frame := make([]byte, 7+len(payload)+1)
	frame[0] = 1
	binary.BigEndian.PutUint16(frame[1:3], 0)
	binary.BigEndian.PutUint32(frame[3:7], uint32(len(payload)))
	copy(frame[7:], payload)
	frame[len(frame)-1] = 0xce
	return frame
}

func looksLikeEPMDResponse(response []byte) bool {
	return len(response) >= 4 &&
		binary.BigEndian.Uint32(response[:4]) == 4369 &&
		bytes.Contains(response[4:], []byte("name "))
}

func epmdNodeSummary(response []byte) string {
	lines := strings.Split(strings.ReplaceAll(string(response), "\r\n", "\n"), "\n")
	nodes := make([]string, 0, 4)
	for _, line := range lines {
		if !strings.HasPrefix(line, "name ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			nodes = append(nodes, fields[1])
		}
		if len(nodes) == 4 {
			break
		}
	}
	return strings.Join(nodes, ",")
}

func cassandraStartupRequest() []byte {
	body := make([]byte, 0, 2+2+len("CQL_VERSION")+2+len("3.0.0"))
	body = appendBigEndianUint16(body, 1)
	body = appendCassandraString(body, "CQL_VERSION")
	body = appendCassandraString(body, "3.0.0")

	frame := make([]byte, 9+len(body))
	frame[0] = 0x04
	frame[4] = 0x01
	binary.BigEndian.PutUint32(frame[5:9], uint32(len(body)))
	copy(frame[9:], body)
	return frame
}

func appendCassandraString(dst []byte, value string) []byte {
	dst = appendBigEndianUint16(dst, uint16(len(value)))
	return append(dst, value...)
}

func appendBigEndianUint16(dst []byte, value uint16) []byte {
	dst = append(dst, 0, 0)
	binary.BigEndian.PutUint16(dst[len(dst)-2:], value)
	return dst
}

func cassandraReadyResponse(response []byte) bool {
	if len(response) < 9 || response[0]&0x80 == 0 {
		return false
	}
	length := int(binary.BigEndian.Uint32(response[5:9]))
	if length < 0 || len(response) < 9+length {
		return false
	}
	return response[4] == 0x02 && length == 0
}

func clickHouseDefaultUserHello() []byte {
	return []byte{
		0x00, 0x11, 'C', 'l', 'i', 'c', 'k', 'H', 'o', 'u', 's', 'e', ' ', 'c', 'l', 'i', 'e', 'n', 't',
		0x15, 0x08, 0xb1, 0xa9, 0x03, 0x00, 0x07, 'd', 'e', 'f', 'a', 'u', 'l', 't', 0x00,
	}
}

func clickHouseServerHello(response []byte) bool {
	return len(response) > 2 && response[0] == 0x00 && bytes.Contains(response[1:], []byte("ClickHouse"))
}
