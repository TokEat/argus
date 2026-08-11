package gopocs

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

const (
	rsyncTestModule   = "backups"
	rsyncTestGreeting = "@RSYNCD: 31.0\n"
)

func rsyncModuleListSteps() []wireStep {
	return []wireStep{
		{request: []byte(RsyncProtocol), response: []byte(rsyncTestGreeting)},
		{
			request:  []byte("\n"),
			response: []byte(rsyncTestModule + "\tTest backups\n@RSYNCD: EXIT\n"),
		},
	}
}

func rsyncAuthRequest(username, password, challenge string) []byte {
	digest := md5.Sum([]byte(password + challenge))
	response := base64.StdEncoding.EncodeToString(digest[:])
	return []byte(fmt.Sprintf("%s %s\n", username, response))
}

func serveRsyncConnections(listener net.Listener, connections ...[]wireStep) error {
	for _, steps := range connections {
		if err := serveWireSteps(listener, steps); err != nil {
			return err
		}
	}
	return nil
}

func TestRsyncUnauthPublishesSuccessfulProtocolAndModuleExchanges(t *testing.T) {
	moduleRequest := []byte(rsyncTestModule + "\n")
	moduleResponse := []byte("@RSYNCD: OK\n")
	listener, done := startScriptedListener(t, func(listener net.Listener) error {
		return serveRsyncConnections(
			listener,
			rsyncModuleListSteps(),
			[]wireStep{
				{request: []byte(RsyncProtocol), response: []byte(rsyncTestGreeting)},
				{request: moduleRequest, response: moduleResponse},
			},
		)
	})
	defer listener.Close()

	var capture goPocCapture
	if err := RsyncScan(capture.hostInfo(t, listener.Addr().String())); err != nil {
		t.Fatal(err)
	}
	waitForScript(t, done)
	capture.assertSingleFinding(t, []structs.GoPocExchange{
		binaryGoPocExchange("Rsync protocol greeting", []byte(RsyncProtocol), []byte(rsyncTestGreeting)),
		binaryGoPocExchange("Rsync module access request", moduleRequest, moduleResponse),
	})
}

func TestRsyncAuthPublishesOnlySuccessfulCredentialExchanges(t *testing.T) {
	moduleRequest := []byte(rsyncTestModule + "\n")
	failedAnonymousChallenge := "failed-anonymous"
	failedBruteChallenge := "failed-brute"
	successChallenge := "verified-success"
	failedResponse := []byte("@ERROR: auth failed\n")
	successChallengeResponse := []byte("@RSYNCD: AUTHREQD " + successChallenge + "\n")
	successAuthRequest := rsyncAuthRequest("root", "123456", successChallenge)
	successResponse := []byte("@RSYNCD: OK\n")

	listener, done := startScriptedListener(t, func(listener net.Listener) error {
		return serveRsyncConnections(
			listener,
			rsyncModuleListSteps(),
			[]wireStep{
				{request: []byte(RsyncProtocol), response: []byte(rsyncTestGreeting)},
				{
					request:  moduleRequest,
					response: []byte("@RSYNCD: AUTHREQD " + failedAnonymousChallenge + "\n"),
				},
				{request: rsyncAuthRequest("", "", failedAnonymousChallenge), response: failedResponse},
			},
			[]wireStep{
				{request: []byte(RsyncProtocol), response: []byte(rsyncTestGreeting)},
				{
					request:  moduleRequest,
					response: []byte("@RSYNCD: AUTHREQD " + failedBruteChallenge + "\n"),
				},
				{request: rsyncAuthRequest("root", "", failedBruteChallenge), response: failedResponse},
			},
			[]wireStep{
				{request: []byte(RsyncProtocol), response: []byte(rsyncTestGreeting)},
				{request: moduleRequest, response: successChallengeResponse},
				{request: successAuthRequest, response: successResponse},
			},
		)
	})
	defer listener.Close()

	var capture goPocCapture
	if err := RsyncScan(capture.hostInfo(t, listener.Addr().String())); err != nil {
		t.Fatal(err)
	}
	waitForScript(t, done)
	capture.assertSingleFinding(t, []structs.GoPocExchange{
		binaryGoPocExchange("Rsync protocol greeting", []byte(RsyncProtocol), []byte(rsyncTestGreeting)),
		binaryGoPocExchange("Rsync module access request", moduleRequest, successChallengeResponse),
		binaryGoPocExchange("Rsync authentication", successAuthRequest, successResponse),
	})
}
