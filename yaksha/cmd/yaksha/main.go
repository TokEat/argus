// Yaksha is a persistent and JSON-lines compatible Yaklang EXP runtime.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/P0lar1ght/argus/yaksha/internal/daemon"
	"github.com/P0lar1ght/argus/yaksha/internal/egress"
	"github.com/P0lar1ght/argus/yaksha/internal/engine"
	"github.com/P0lar1ght/argus/yaksha/internal/inspector"
	"github.com/P0lar1ght/argus/yaksha/internal/protocol"
	"github.com/P0lar1ght/argus/yaksha/internal/testrunner"
	"github.com/P0lar1ght/argus/yaksha/internal/validator"
)

func main() {
	mode := "worker"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "serve":
		if err := serve(); err != nil {
			fmt.Fprintln(os.Stderr, "yaksha:", err)
			os.Exit(1)
		}
	case "worker":
		if err := runJSONLines(os.Stdin, workerResponseWriter(), workerEgress()); err != nil {
			fmt.Fprintln(os.Stderr, "yaksha:", err)
			os.Exit(1)
		}
	case "healthcheck":
		if err := healthcheck(); err != nil {
			fmt.Fprintln(os.Stderr, "yaksha:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "yaksha: unsupported mode %q\n", mode)
		os.Exit(2)
	}
}

func workerResponseWriter() io.Writer {
	if os.Getenv("YAKSHA_RESPONSE_FD") == "4" {
		if file := os.NewFile(4, "yaksha-response"); file != nil {
			return file
		}
	}
	return os.Stdout
}

func healthcheck() error {
	endpoint := os.Getenv("YAKSHA_HEALTHCHECK_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8790/readyz"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("readyz returned HTTP %d", response.StatusCode)
	}
	return nil
}

func serve() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	config, err := daemon.ConfigFromEnv(executable)
	if err != nil {
		return err
	}
	server, err := daemon.New(config)
	if err != nil {
		return err
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	err = server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func workerEgress() egress.Client {
	if os.Getenv("YAKSHA_EGRESS_FD") == "3" {
		file := os.NewFile(3, "yaksha-egress")
		if file != nil {
			return egress.NewIPCClient(file)
		}
	}
	return egress.DisabledClient{}
}

func runJSONLines(reader io.Reader, writer io.Writer, outbound egress.Client) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), protocol.MaxRequestLineBytes)
	buffered := bufio.NewWriter(writer)
	for scanner.Scan() {
		req, err := protocol.ParseRequest(scanner.Text())
		if err != nil {
			writeResponse(buffered, protocol.Response{ID: req.ID, Status: protocol.StatusInternalError, Context: protocol.ExecutionContextFor(req), Error: err.Error()})
			continue
		}
		switch req.Action {
		case protocol.ActionInspect:
			if len(req.Dependencies) > 0 || len(req.Assets) > 0 || len(req.NetworkTargets) > 0 || req.Egress != nil {
				writeResponse(buffered, protocol.Response{ID: req.ID, Action: req.Action, Status: protocol.StatusInternalError, Context: protocol.ExecutionContextFor(req), Error: "inspect accepts source only; sealed resolver, egress, and network targets are not allowed"})
				continue
			}
			inspection := inspector.Inspect(req.Script)
			writeResponse(buffered, protocol.Response{ID: req.ID, Action: req.Action, Status: protocol.StatusSucceeded, Context: protocol.ExecutionContextFor(req), Inspection: &inspection})
		case protocol.ActionValidate:
			result := validator.Validate(req)
			writeResponse(buffered, protocol.Response{ID: req.ID, Action: req.Action, Status: protocol.StatusSucceeded, Context: protocol.ExecutionContextFor(req), Inspection: &result.Inspection, Validation: &result.Validation})
		case protocol.ActionTest:
			report := testrunner.Run(req)
			writeResponse(buffered, protocol.Response{ID: req.ID, Action: req.Action, Status: protocol.StatusSucceeded, Context: protocol.ExecutionContextFor(req), Test: &report})
		default:
			response := engine.ExecuteWithEgress(req, outbound)
			response.Action = req.Action
			writeResponse(buffered, response)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stdin error: %w", err)
	}
	return nil
}

func writeResponse(writer *bufio.Writer, response protocol.Response) {
	raw, err := protocol.EncodeResponse(response)
	if err != nil {
		raw, _ = protocol.EncodeResponse(protocol.Response{ID: response.ID, Status: protocol.StatusInternalError, Context: response.Context, Error: fmt.Sprintf("response encoding failed: %v", err)})
	}
	_, _ = writer.Write(append(raw, '\n'))
	_ = writer.Flush()
}
