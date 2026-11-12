// Package daemon exposes the persistent Yaksha HTTP runtime and supervises a
// pool of pre-warmed JSON-lines worker processes.
package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/TokEat/argus/yaksha/internal/egress"
	"github.com/TokEat/argus/yaksha/internal/protocol"
)

const workerGrace = 5 * time.Second

type Config struct {
	Addr         string
	WorkerPath   string
	Workers      int
	Queue        int
	RecycleAfter int
	WorkerEnv    []string
	RelayAddress string
	RelayToken   string
}

func DefaultConfig(workerPath string) Config {
	return Config{Addr: "127.0.0.1:8790", WorkerPath: workerPath, Workers: 2, Queue: 32, RecycleAfter: 100}
}

type Server struct {
	pool *pool
	http *http.Server
}

func New(config Config) (*Server, error) {
	if config.Workers < 1 || config.Workers > 16 || config.Queue < 0 || config.Queue > 1024 || config.RecycleAfter < 1 {
		return nil, fmt.Errorf("invalid Yaksha daemon worker configuration")
	}
	p, err := newPool(config)
	if err != nil {
		return nil, err
	}
	server := &Server{pool: p}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.health)
	mux.HandleFunc("GET /readyz", server.ready)
	mux.HandleFunc("POST /v1/execute", server.execute)
	server.http = &http.Server{Addr: config.Addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return server, nil
}

func (s *Server) ListenAndServe() error { return s.http.ListenAndServe() }

func (s *Server) Shutdown(ctx context.Context) error {
	err := s.http.Shutdown(ctx)
	s.pool.close()
	return err
}

func (s *Server) Handler() http.Handler { return s.http.Handler }

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	if !s.pool.ready() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "workers": s.pool.live.Load()})
}

func (s *Server) execute(w http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(io.LimitReader(request.Body, protocol.MaxRequestLineBytes+1))
	if err != nil || len(body) > protocol.MaxRequestLineBytes {
		writeProtocolError(w, http.StatusRequestEntityTooLarge, "Yaksha request exceeds protocol limits")
		return
	}
	req, err := protocol.ParseRequest(strings.TrimSpace(string(body)))
	if err != nil {
		writeProtocolError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Action == protocol.ActionInspect && (len(req.Dependencies) > 0 || len(req.Assets) > 0 || len(req.NetworkTargets) > 0 || req.Egress != nil) {
		writeProtocolError(w, http.StatusBadRequest, "inspect accepts source only; sealed resolver and network targets are not allowed")
		return
	}
	ctx := request.Context()
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Duration(protocol.DefaultTimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout+workerGrace)
	defer cancel()
	outbound, err := selectedEgressWithConfig(ctx, req, s.pool.config)
	if err != nil {
		writeProtocolError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Proxy credentials are a daemon-only transport secret. Workers receive a
	// canonical request with the egress selector removed.
	req.Egress = nil
	payload, err := json.Marshal(req)
	if err != nil {
		writeProtocolError(w, http.StatusBadRequest, "encode worker request")
		return
	}
	response, status, err := s.pool.execute(ctx, append(payload, '\n'), outbound)
	if err != nil {
		writeProtocolError(w, status, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func writeProtocolError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, protocol.Response{ID: "daemon", Status: protocol.StatusInternalError, Error: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type pool struct {
	config    Config
	available chan *worker
	admission chan struct{}
	done      chan struct{}
	live      atomic.Int64
	nextID    atomic.Uint64
	closeOnce sync.Once
	replenish sync.Mutex
	workersMu sync.Mutex
	workers   map[*worker]struct{}
}

func newPool(config Config) (*pool, error) {
	p := &pool{
		config: config, available: make(chan *worker, config.Workers),
		admission: make(chan struct{}, config.Workers+config.Queue), done: make(chan struct{}),
		workers: make(map[*worker]struct{}),
	}
	for index := 0; index < config.Workers; index++ {
		item, err := p.startWorker()
		if err != nil {
			p.close()
			return nil, fmt.Errorf("start Yaksha worker: %w", err)
		}
		p.available <- item
	}
	return p, nil
}

func (p *pool) ready() bool { return len(p.available) > 0 }

func (p *pool) execute(ctx context.Context, request []byte, outbound egress.Client) ([]byte, int, error) {
	select {
	case p.admission <- struct{}{}:
		defer func() { <-p.admission }()
	default:
		return nil, http.StatusTooManyRequests, fmt.Errorf("Yaksha worker queue is full")
	}
	var item *worker
	select {
	case item = <-p.available:
	case <-ctx.Done():
		return nil, http.StatusGatewayTimeout, ctx.Err()
	case <-p.done:
		return nil, http.StatusServiceUnavailable, fmt.Errorf("Yaksha daemon is shutting down")
	}
	item.route.SetContext(ctx, outbound)
	response, err := item.call(ctx, request)
	item.route.Clear()
	healthy := err == nil && item.lastStatus != protocol.StatusTimeout && item.lastStatus != protocol.StatusCanceled && item.lastStatus != protocol.StatusInternalError
	retire := !healthy || item.requests >= p.config.RecycleAfter
	if retire {
		p.replace(item, healthy)
	} else {
		p.available <- item
	}
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			status = http.StatusGatewayTimeout
		}
		return nil, status, err
	}
	return response, http.StatusOK, nil
}

func (p *pool) replace(old *worker, oldHealthy bool) {
	replacement, err := p.startWorker()
	if err == nil {
		old.close()
		p.available <- replacement
		return
	}
	if oldHealthy {
		p.available <- old
		return
	}
	old.close()
	go p.replenishWorkers()
}

func (p *pool) replenishWorkers() {
	p.replenish.Lock()
	defer p.replenish.Unlock()
	for p.live.Load() < int64(p.config.Workers) {
		select {
		case <-p.done:
			return
		default:
		}
		item, err := p.startWorker()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		p.available <- item
	}
}

func (p *pool) startWorker() (*worker, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	parent := os.NewFile(uintptr(pair[0]), "yaksha-egress-parent")
	child := os.NewFile(uintptr(pair[1]), "yaksha-egress-child")
	cmd := exec.Command(p.config.WorkerPath, "worker")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		parent.Close()
		child.Close()
		return nil, err
	}
	responseRead, responseWrite, err := os.Pipe()
	if err != nil {
		parent.Close()
		child.Close()
		stdin.Close()
		return nil, err
	}
	// VM errors are returned through the bounded JSON response. Never attach
	// script-controlled stderr to the long-lived daemon log because Yaklang
	// async panic text can contain parameters or target secrets.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.ExtraFiles = []*os.File{child, responseWrite}
	cmd.Env = append(append([]string{}, p.config.WorkerEnv...), "YAKSHA_EGRESS_FD=3", "YAKSHA_RESPONSE_FD=4")
	if err := cmd.Start(); err != nil {
		parent.Close()
		child.Close()
		stdin.Close()
		responseRead.Close()
		responseWrite.Close()
		return nil, err
	}
	_ = child.Close()
	_ = responseWrite.Close()
	p.live.Add(1)
	route := &egress.ScopedClient{}
	route.Clear()
	item := &worker{id: p.nextID.Add(1), cmd: cmd, stdin: stdin, stdout: bufio.NewScanner(responseRead), response: responseRead, egress: parent, route: route, owner: p}
	item.stdout.Buffer(make([]byte, 64*1024), protocol.MaxResponseLineBytes)
	p.workersMu.Lock()
	p.workers[item] = struct{}{}
	p.workersMu.Unlock()
	go func() { _ = egress.ServeIPC(parent, route) }()
	return item, nil
}

func (p *pool) close() {
	p.closeOnce.Do(func() {
		close(p.done)
		p.workersMu.Lock()
		items := make([]*worker, 0, len(p.workers))
		for item := range p.workers {
			items = append(items, item)
		}
		p.workersMu.Unlock()
		for _, item := range items {
			item.close()
		}
	})
}

type worker struct {
	id         uint64
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdout     *bufio.Scanner
	response   *os.File
	egress     *os.File
	route      *egress.ScopedClient
	owner      *pool
	requests   int
	lastStatus string
	closed     atomic.Bool
}

func (w *worker) call(ctx context.Context, request []byte) ([]byte, error) {
	if _, err := w.stdin.Write(request); err != nil {
		return nil, fmt.Errorf("write worker %d request: %w", w.id, err)
	}
	type scanResult struct {
		line []byte
		err  error
	}
	result := make(chan scanResult, 1)
	go func() {
		if !w.stdout.Scan() {
			err := w.stdout.Err()
			if err == nil {
				err = fmt.Errorf("worker exited before returning a response")
			}
			result <- scanResult{err: err}
			return
		}
		result <- scanResult{line: append([]byte(nil), w.stdout.Bytes()...)}
	}()
	select {
	case scanned := <-result:
		if scanned.err != nil {
			return nil, scanned.err
		}
		var response protocol.Response
		if err := json.Unmarshal(scanned.line, &response); err != nil {
			return nil, fmt.Errorf("worker %d returned invalid JSON: %w", w.id, err)
		}
		if response.Status == "" {
			return nil, fmt.Errorf("worker %d returned a response without status", w.id)
		}
		w.lastStatus = response.Status
		w.requests++
		return scanned.line, nil
	case <-ctx.Done():
		_ = w.cmd.Process.Kill()
		return nil, ctx.Err()
	}
}

func (w *worker) close() {
	if !w.closed.CompareAndSwap(false, true) {
		return
	}
	_ = w.stdin.Close()
	_ = w.response.Close()
	_ = w.egress.Close()
	if w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
	}
	_ = w.cmd.Wait()
	w.owner.workersMu.Lock()
	delete(w.owner.workers, w)
	w.owner.workersMu.Unlock()
	w.owner.live.Add(-1)
}

func ConfigFromEnv(workerPath string) (Config, error) {
	config := DefaultConfig(workerPath)
	if value := strings.TrimSpace(os.Getenv("YAKSHA_LISTEN_ADDR")); value != "" {
		config.Addr = value
	}
	var err error
	if config.Workers, err = envInt("YAKSHA_WORKERS", config.Workers); err != nil {
		return Config{}, err
	}
	if config.Queue, err = envInt("YAKSHA_QUEUE_SIZE", config.Queue); err != nil {
		return Config{}, err
	}
	if config.RecycleAfter, err = envInt("YAKSHA_RECYCLE_AFTER", config.RecycleAfter); err != nil {
		return Config{}, err
	}
	config.WorkerEnv = workerEnv()
	config.RelayAddress = strings.TrimSpace(os.Getenv("YAKSHA_RELAY_ADDR"))
	config.RelayToken = strings.TrimSpace(os.Getenv("YAKSHA_RELAY_TOKEN"))
	if (config.RelayAddress == "") != (config.RelayToken == "") {
		return Config{}, fmt.Errorf("YAKSHA_RELAY_ADDR and YAKSHA_RELAY_TOKEN are required together")
	}
	return config, nil
}

func selectedEgress(req protocol.Request) (egress.Client, error) {
	return selectedEgressWithConfig(context.Background(), req, Config{})
}

func selectedEgressWithConfig(ctx context.Context, req protocol.Request, config Config) (egress.Client, error) {
	// Static validation and fixture tests never establish real connections.
	if req.Action == protocol.ActionValidate || req.Action == protocol.ActionTest {
		return egress.DisabledClient{}, nil
	}
	if req.Egress == nil || req.Egress.Mode == protocol.EgressDisabled {
		return egress.DisabledClient{}, nil
	}
	switch req.Egress.Mode {
	case protocol.EgressDirect:
		return egress.WithConnectionBudget(egress.NewDirectClient(nil, false), egress.MaxConnectionsPerRun), nil
	case protocol.EgressSOCKS5:
		client, err := egress.NewSOCKS5Client(req.Egress.SOCKS5Proxy)
		return egress.WithConnectionBudget(client, egress.MaxConnectionsPerRun), err
	case protocol.EgressRelay:
		client, err := egress.NewRelayClient(ctx, config.RelayAddress, config.RelayToken, req.Egress.RouteID)
		return egress.WithConnectionBudget(client, egress.MaxConnectionsPerRun), err
	default:
		return nil, fmt.Errorf("unsupported Yaksha egress mode")
	}
}

func envInt(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	return parsed, nil
}

func workerEnv() []string {
	result := []string{}
	for _, key := range []string{"PATH", "LANG", "LC_ALL", "TZ", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if value, ok := os.LookupEnv(key); ok {
			result = append(result, key+"="+value)
		}
	}
	return result
}
