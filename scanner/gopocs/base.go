package gopocs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"net"
	"os"
	"strings"
	"sync"
)

var PluginList = map[string]interface{}{
	"NetBios-GetHostInfo": NetBIOS,
	"RPC-GetHostInfo":     Findnet,
	"SSH-Crack":           SshScan,
	"FTP-Crack":           FtpScan,
	"Mysql-Crack":         MysqlScan,
	"Mssql-Crack":         MssqlScan,
	"Oracle-Crack":        OracleScan,
	"MongoDB-Crack":       MongodbScan,
	"RDP-Crack":           RdpScan,
	"Redis-Crack":         RedisScan,
	"SMB-MS17-010":        MS17010,
	"PostgreSQL-Crack":    PostgresScan,
	"SMB-Crack":           SmbScan,
	"Telnet-Crack":        TelnetScan,
	"Memcache-Crack":      MemcachedScan,
	"JDWP-Scan":           JDWPScan,
	"Shiro-Key-Crack":     ShiroKeyCheck,
	"ADB-Scan":            ADBScan,
	"Telnet-Bypass":       TelnetBypassScan,
	"ViewState-Key-Crack": ViewStateKeyCheck,
	"VNC-Scan":            VncScan,
	"Rsync-Scan":          RsyncScan,
	"DM-Scan":             DmScan,
	"Kingbase-Scan":       KingbaseScan,
	"DNP3-Scan":           DNP3Scan,
	"S7-Scan":             S7Scan,
	"EtherNetIP-Scan":     EtherNetIPScan,
	"ATG-Scan":            ATGScan,
	"MELSEC-Scan":         MELSECScan,
	"FINS-Scan":           FINSScan,
	"Crimson-Scan":        CrimsonScan,
	"IEC104-Scan":         IEC104Scan,
	"LDAP-Scan":           LDAPScan,
	"Zookeeper-Scan":      ZookeeperScan,
	"MQTT-Scan":           MQTTScan,
	"Cassandra-Scan":      CassandraScan,
	"ClickHouse-Scan":     ClickHouseScan,
	"ActiveMQ-Scan":       ActiveMQScan,
	"RMI-Scan":            RMIScan,
	"SVN-Scan":            SVNScan,
	"HsqlDb-Scan":         HsqlDbScan,
	"TiDB-Scan":           TiDBScan,
	"Nacos-Raft-Scan":     NacosRaftScan,
	"MSMQ-Scan":           MSMQScan,
	"SAP-P4-Scan":         SAPP4Scan,
	"Telnet-CVE-Scan":     TelnetCVEScan,
}

func InitDictionaries() {
	initDic()
}

func ReadBytes(conn net.Conn) (result []byte, err error) {
	size := 4096
	buf := make([]byte, size)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result = append(result, buf[0:count]...)
		if count < size {
			break
		}
	}
	if len(result) > 0 {
		err = nil
	}
	return result, err
}

var key = "0123456789abcdef"

func AesEncrypt(orig string, key string) string {
	// 转成字节数组
	origData := []byte(orig)
	k := []byte(key)
	// 分组秘钥
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 补全码
	origData = PKCS7Padding(origData, blockSize)
	// 加密模式
	blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])
	// 创建数组
	cryted := make([]byte, len(origData))
	// 加密
	blockMode.CryptBlocks(cryted, origData)
	return base64.StdEncoding.EncodeToString(cryted)
}
func AesDecrypt(cryted string, key string) string {
	// 转成字节数组
	crytedByte, _ := base64.StdEncoding.DecodeString(cryted)
	k := []byte(key)
	// 分组秘钥
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 加密模式
	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
	// 创建数组
	orig := make([]byte, len(crytedByte))
	// 解密
	blockMode.CryptBlocks(orig, crytedByte)
	// 去补全码
	orig = PKCS7UnPadding(orig)
	return string(orig)
}

// 补码
// AES加密数据块分组长度必须为128bit(byte[16])，密钥长度可以是128bit(byte[16])、192bit(byte[24])、256bit(byte[32])中的任意一个。
func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
	padding := blocksize - len(ciphertext)%blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// 去码
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func generateKeys(key string) []string {
	var results []string
	results = append(results, strings.ToLower(key))
	results = append(results, strings.ToUpper(key))
	results = append(results, strings.ToUpper(strings.ToUpper(key[:1])+key[1:]))
	return results
}

func splitUserPass(userPasswd string) (user string, oriPass string) {
	sp := strings.Split(userPasswd, " : ")
	user = ""
	oriPass = ""
	if len(sp) != 2 {
		user = sp[0]
		oriPass = ""
	} else {
		user = sp[0]
		oriPass = sp[1]
	}
	user = strings.TrimSuffix(user, "\r")
	oriPass = strings.TrimSuffix(oriPass, "\r")
	return user, oriPass
}

func sortUserPassword(info *structs.HostInfo, UserPasswdDict string, DefaultKeys []string) []structs.UserPasswd {
	var userPasswdList []structs.UserPasswd
	var upList []string
	if info.Password != "" {
		upList = append(upList, info.Password)
	} else if info.PasswordFile != "" {
		b, err := os.ReadFile(info.PasswordFile)
		if err == nil {
			t := strings.ReplaceAll(string(b), "\r\n", "\n")
			for _, v := range strings.Split(t, "\n") {
				if !strings.Contains(v, " : ") {
					continue
				}
				upList = append(upList, v)
			}
		}
	} else {
		upList = info.UserPass
		// 兼容Windows
		UserPasswdDict = strings.ReplaceAll(UserPasswdDict, "\r\n", "\n")
		for _, v := range strings.Split(UserPasswdDict, "\n") {
			upList = append(upList, v)
		}
	}
	upList = utils.RemoveDuplicateElement(upList)

	// 统计变形后的字典
	for _, userPasswd := range upList {
		user, oriPass := splitUserPass(userPasswd)

		if strings.Contains(oriPass, "{{key}}") {
			for _, sKey := range info.InfoStr {
				newKeys := generateKeys(sKey)
				for _, nKey := range newKeys {
					newPass := strings.Replace(oriPass, "{{key}}", nKey, -1)
					userPasswdList = append(userPasswdList, structs.UserPasswd{UserName: user, Password: newPass})
				}

			}
			for _, dk := range DefaultKeys {
				newKeys := generateKeys(dk)
				for _, nKey := range newKeys {
					newPass := strings.Replace(oriPass, "{{key}}", nKey, -1)
					userPasswdList = append(userPasswdList, structs.UserPasswd{UserName: user, Password: newPass})
				}
			}

		} else {
			userPasswdList = append(userPasswdList, structs.UserPasswd{UserName: user, Password: oriPass})
		}
	}
	return RemoveDuplicateUserPass(userPasswdList)
}

func RemoveDuplicateUserPass(input []structs.UserPasswd) []structs.UserPasswd {
	temp := map[structs.UserPasswd]struct{}{}
	var result []structs.UserPasswd
	for _, item := range input {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func CheckErrs(err error) bool {
	if err == nil {
		return false
	}
	errs := []string{
		"closed by the remote host", "too many connections",
		"i/o timeout", "EOF", "A connection attempt failed",
		"established connection failed", "connection attempt failed",
		"Unable to read", "is not allowed to connect to this",
		"no pg_hba.conf entry",
		"No connection could be made",
		"invalid packet size",
		"bad connection",
	}
	for _, key := range errs {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(key)) {
			return true
		}
	}
	return false
}

func writeResult(info *structs.HostInfo, result structs.GoPocsResultType) {
	if info != nil && info.WriteResult != nil {
		info.WriteResult(result)
	}
}

func binaryGoPocExchange(label string, request, response []byte) structs.GoPocExchange {
	return structs.GoPocExchange{
		Label:    label,
		Request:  hex.Dump(request),
		Response: hex.Dump(response),
		Encoding: "hex-dump",
	}
}

func binaryGoPocWriteExchange(label string, request []byte, written int, response []byte) structs.GoPocExchange {
	if written < 0 {
		written = 0
	}
	if written > len(request) {
		written = len(request)
	}
	return binaryGoPocExchange(label, request[:written], response)
}

// successfulSessionEvidenceLimit bounds the amount of raw protocol data kept
// for one credential attempt. Each attempt owns its recorder; failed attempts
// are discarded and never contribute bytes to a later successful finding.
const successfulSessionEvidenceLimit = 4 << 20

var errSuccessfulSessionEvidenceLimit = errors.New("successful GoPoc session evidence limit exceeded")

type recordedIODirection uint8

const (
	recordedIORead recordedIODirection = iota
	recordedIOWrite
)

type recordedIOEvent struct {
	direction recordedIODirection
	data      []byte
}

// boundedRecordingConn records exactly the bytes accepted by Write and
// returned by Read, in call order. It deliberately sits below protocol
// libraries (and below any TLS layer those libraries create), so the report
// contains the actual wire bytes rather than reconstructed messages. Reaching
// the evidence limit stops copying but does not alter authentication I/O; the
// caller fails closed only if that credential session ultimately succeeds.
type boundedRecordingConn struct {
	net.Conn

	ioGate sync.RWMutex
	closed bool
	mu     sync.Mutex
	limit  int
	used   int
	events []recordedIOEvent
	err    error
}

func newBoundedRecordingConn(conn net.Conn, limit int) *boundedRecordingConn {
	return &boundedRecordingConn{Conn: conn, limit: limit}
}

func (conn *boundedRecordingConn) Read(buffer []byte) (int, error) {
	conn.ioGate.RLock()
	defer conn.ioGate.RUnlock()
	if conn.closed {
		return 0, net.ErrClosed
	}

	n, readErr := conn.Conn.Read(buffer)
	recordErr := conn.record(recordedIORead, buffer[:max(n, 0)])
	return n, errors.Join(readErr, recordErr)
}

func (conn *boundedRecordingConn) Write(buffer []byte) (int, error) {
	conn.ioGate.RLock()
	defer conn.ioGate.RUnlock()
	if conn.closed {
		return 0, net.ErrClosed
	}

	n, writeErr := conn.Conn.Write(buffer)
	recordErr := conn.record(recordedIOWrite, buffer[:max(n, 0)])
	return n, errors.Join(writeErr, recordErr)
}

func (conn *boundedRecordingConn) Close() error {
	closeErr := conn.Conn.Close()
	conn.ioGate.Lock()
	conn.closed = true
	conn.ioGate.Unlock()
	return closeErr
}

func (conn *boundedRecordingConn) record(direction recordedIODirection, data []byte) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.err != nil {
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	if conn.limit < 0 || len(data) > conn.limit-conn.used {
		conn.events = nil
		conn.err = fmt.Errorf("%w (limit: %d bytes)", errSuccessfulSessionEvidenceLimit, conn.limit)
		return nil
	}

	copyOfData := append([]byte(nil), data...)
	conn.events = append(conn.events, recordedIOEvent{direction: direction, data: copyOfData})
	conn.used += len(copyOfData)
	return nil
}

func (conn *boundedRecordingConn) recordingError() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.err
}

func (conn *boundedRecordingConn) exchanges(label string) ([]structs.GoPocExchange, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.err != nil {
		return nil, conn.err
	}
	exchanges := make([]structs.GoPocExchange, 0, len(conn.events))
	for index, event := range conn.events {
		eventLabel := fmt.Sprintf("%s wire I/O #%d", label, index+1)
		if event.direction == recordedIOWrite {
			exchanges = append(exchanges, binaryGoPocExchange(eventLabel+" request", event.data, nil))
			continue
		}
		exchanges = append(exchanges, binaryGoPocExchange(eventLabel+" response", nil, event.data))
	}
	return exchanges, nil
}

func captureSuccessfulSessionEvidence(conn net.Conn, label string, limit int, operation func(net.Conn) error) ([]structs.GoPocExchange, error) {
	recorder := newBoundedRecordingConn(conn, limit)
	operationErr := operation(recorder)
	// Every credential attempt already owns a short-lived connection. Closing
	// it here also waits out library background readers before the snapshot.
	_ = recorder.Close()
	if operationErr != nil {
		return nil, operationErr
	}
	if recordErr := recorder.recordingError(); recordErr != nil {
		return nil, recordErr
	}
	return recorder.exchanges(label)
}

func isSuccessfulSessionEvidenceError(err error) bool {
	return errors.Is(err, errSuccessfulSessionEvidenceLimit)
}

func emitOutput(info *structs.HostInfo, msg ddout.OutputMessage) {
	if info != nil && info.Emit != nil {
		info.Emit(msg)
		return
	}
	ddout.FormatOutput(msg)
}

func readDict(name string) string {
	bt, err := os.ReadFile(name)
	if err != nil {
		return ""
	}
	return string(bt)
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// initDic 初始化用于爆破的字典
func initDic() {
	basePath := "config/dict/"

	if fileExists(basePath + "ftp.txt") {
		ftpUserPasswdDict = readDict(basePath + "ftp.txt")
	}
	if fileExists(basePath + "mssql.txt") {
		mssqlUserPasswdDict = readDict(basePath + "mssql.txt")
	}
	if fileExists(basePath + "mysql.txt") {
		mysqlUserPasswdDict = readDict(basePath + "mysql.txt")
	}
	if fileExists(basePath + "oracle.txt") {
		oracleUserPasswdDict = readDict(basePath + "oracle.txt")
	}
	if fileExists(basePath + "postgresql.txt") {
		postgreSQLUserPasswdDict = readDict(basePath + "postgresql.txt")
	}
	if fileExists(basePath + "rdp.txt") {
		rdpUserPasswdDict = readDict(basePath + "rdp.txt")
	}
	if fileExists(basePath + "redis.txt") {
		redisUserPasswdDict = readDict(basePath + "redis.txt")
	}
	if fileExists(basePath + "smb.txt") {
		smbUserPasswdDict = readDict(basePath + "smb.txt")
	}
	if fileExists(basePath + "ssh.txt") {
		sshUserPasswdDict = readDict(basePath + "ssh.txt")
	}
	if fileExists(basePath + "telnet.txt") {
		telnetUserPasswdDict = readDict(basePath + "telnet.txt")
	}
	if fileExists(basePath + "shirokeys.txt") {
		ShiroKeys = readDict(basePath + "shirokeys.txt")
	}

}
