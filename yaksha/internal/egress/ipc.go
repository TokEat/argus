package egress

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

type ipcRequest struct {
	Operation string   `json:"operation"`
	Target    string   `json:"target"`
	Allowed   []string `json:"allowed"`
}

type ipcResponse struct {
	HTTP   *HTTPResult `json:"http,omitempty"`
	Result string      `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type IPCClient struct {
	mu      sync.Mutex
	encoder *json.Encoder
	decoder *json.Decoder
}

func NewIPCClient(stream io.ReadWriter) *IPCClient {
	return &IPCClient{encoder: json.NewEncoder(stream), decoder: json.NewDecoder(bufio.NewReader(stream))}
}

func (c *IPCClient) HTTPGet(ctx context.Context, target string, allowed []string) (HTTPResult, error) {
	response, err := c.call(ctx, ipcRequest{Operation: "http_get", Target: target, Allowed: allowed})
	if err != nil {
		return HTTPResult{}, err
	}
	if response.HTTP == nil {
		return HTTPResult{}, fmt.Errorf("egress IPC returned no HTTP result")
	}
	return *response.HTTP, nil
}

func (c *IPCClient) Dial(ctx context.Context, target string, allowed []string) (string, error) {
	response, err := c.call(ctx, ipcRequest{Operation: "dial", Target: target, Allowed: allowed})
	if err != nil {
		return "", err
	}
	return response.Result, nil
}

func (c *IPCClient) call(ctx context.Context, request ipcRequest) (ipcResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ipcResponse{}, err
	}
	if err := c.encoder.Encode(request); err != nil {
		return ipcResponse{}, fmt.Errorf("write egress IPC request: %w", err)
	}
	var response ipcResponse
	if err := c.decoder.Decode(&response); err != nil {
		return ipcResponse{}, fmt.Errorf("read egress IPC response: %w", err)
	}
	if response.Error != "" {
		return response, fmt.Errorf("%s", response.Error)
	}
	return response, nil
}

func ServeIPC(stream io.ReadWriter, client Client) error {
	decoder := json.NewDecoder(bufio.NewReader(stream))
	encoder := json.NewEncoder(stream)
	for {
		var request ipcRequest
		if err := decoder.Decode(&request); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		response := ipcResponse{}
		switch request.Operation {
		case "http_get":
			result, err := client.HTTPGet(context.Background(), request.Target, request.Allowed)
			if err != nil {
				response.Error = err.Error()
			} else {
				response.HTTP = &result
			}
		case "dial":
			result, err := client.Dial(context.Background(), request.Target, request.Allowed)
			if err != nil {
				response.Error = err.Error()
			} else {
				response.Result = result
			}
		default:
			response.Error = "unsupported egress IPC operation"
		}
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
}
