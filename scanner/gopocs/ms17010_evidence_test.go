package gopocs

import (
	"bytes"
	"sync"
	"testing"
)

func TestMS17010ProbeRequestsAreTaskLocal(t *testing.T) {
	originalTree := append([]byte(nil), treeConnectRequest...)
	originalPipe := append([]byte(nil), transNamedPipeRequest...)

	const workers = 64
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(value byte) {
			defer wait.Done()
			_, _, tree, pipe := cloneMS17010ProbeRequests()
			tree[32], tree[33] = value, value+1
			pipe[28], pipe[29], pipe[32], pipe[33] = value+2, value+3, value+4, value+5
		}(byte(worker))
	}
	wait.Wait()

	if !bytes.Equal(treeConnectRequest, originalTree) {
		t.Fatal("global tree-connect request was mutated by a task-local probe")
	}
	if !bytes.Equal(transNamedPipeRequest, originalPipe) {
		t.Fatal("global named-pipe request was mutated by a task-local probe")
	}
}
