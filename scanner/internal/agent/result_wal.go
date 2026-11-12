package agent

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	pb "github.com/TokEat/argus/shared/proto/go/scan"
	"google.golang.org/protobuf/proto"
)

// resultWAL 是结果流的磁盘追加缓冲：帧格式为 [8 字节 big-endian 长度][proto.Marshal(ScanResult)]。
// 它让 Agent 在结果流断线（server 不可达 / 网络抖动）但进程存活时，把已产生的帧落到磁盘，
// 重连后按序重放（服务端结果写入幂等，重复帧只 upsert），从而不丢结果。
//
// 设计取舍：
//   - 只面向「进程存活、网络断」的恢复；进程崩溃由 server 端回收+重试兜底（见 node_recycle），
//     因此 Append 只 flush 到内核、不做每帧 fsync，避免拖慢扫描热路径。
//   - Replay 容忍尾部半帧（崩溃/掉电残留）：读到坏帧即视为结束，已读出的完整帧照常回放。
//   - 单任务一个 WAL 文件，CloseAndRecv 成功后由 Discard 删除，寿命与任务尝试一致。
type resultWAL struct {
	path  string
	file  *os.File
	w     *bufio.Writer
	count int
}

// walFramePrefixLen 是帧头长度（8 字节 big-endian 长度前缀）。
const walFramePrefixLen = 8

// maxWALFrameBytes 是单帧体上限，超出即视为坏帧。结果帧为 JSON 负载，正常远小于该值。
const maxWALFrameBytes = 64 << 20 // 64 MiB

// WALPath 返回某任务尝试的 WAL 文件路径。
func WALPath(spoolDir, taskID string) string {
	safe := filepath.Base(taskID)
	return filepath.Join(spoolDir, safe+".wal")
}

// OpenWAL 打开（或创建/截断）某任务的 WAL 文件，返回追加写入器。
func OpenWAL(spoolDir, taskID string) (*resultWAL, error) {
	if spoolDir == "" {
		return nil, errors.New("wal spool dir is empty")
	}
	if taskID == "" {
		return nil, errors.New("wal task id is empty")
	}
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		return nil, fmt.Errorf("create wal spool dir: %w", err)
	}
	path := WALPath(spoolDir, taskID)
	// O_RDWR：同一句柄既要 Append（写）也要 Replay（读+Seek），避免为重放开第二个句柄。
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open wal %s: %w", path, err)
	}
	return &resultWAL{path: path, file: f, w: bufio.NewWriter(f)}, nil
}

// OpenWALForReplay 以只读方式打开已有 WAL（不清空），供断线重连后回放。
func OpenWALForReplay(spoolDir, taskID string) (*resultWAL, error) {
	if spoolDir == "" || taskID == "" {
		return nil, errors.New("wal spool dir and task id are required")
	}
	path := WALPath(spoolDir, taskID)
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return &resultWAL{path: path, file: f}, nil
}

// Append 追加一帧并 flush 到内核（不 fsync）。
func (w *resultWAL) Append(res *pb.ScanResult) error {
	if w == nil || w.w == nil {
		return errors.New("wal is not open for write")
	}
	buf, err := proto.Marshal(res)
	if err != nil {
		return fmt.Errorf("marshal scan result for wal: %w", err)
	}
	var prefix [walFramePrefixLen]byte
	binary.BigEndian.PutUint64(prefix[:], uint64(len(buf)))
	if _, err := w.w.Write(prefix[:]); err != nil {
		return fmt.Errorf("write wal frame prefix: %w", err)
	}
	if _, err := w.w.Write(buf); err != nil {
		return fmt.Errorf("write wal frame body: %w", err)
	}
	if err := w.w.Flush(); err != nil {
		return fmt.Errorf("flush wal frame: %w", err)
	}
	w.count++
	return nil
}

// Replay 从第 from 帧起顺序读出并回调 fn；EOF 或尾部坏帧都视为正常结束。
// fn 返回错误时终止回放并透传该错误。
func (w *resultWAL) Replay(from int, fn func(*pb.ScanResult) error) error {
	if w == nil || w.file == nil {
		return errors.New("wal is not open for read")
	}
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek wal: %w", err)
	}
	r := bufio.NewReader(w.file)
	idx := 0
	for {
		var prefix [walFramePrefixLen]byte
		if _, err := io.ReadFull(r, prefix[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return fmt.Errorf("read wal frame prefix: %w", err)
		}
		length := binary.BigEndian.Uint64(prefix[:])
		if length == 0 || length > maxWALFrameBytes {
			// 坏帧/截断：视为结束。
			return nil
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(r, body); err != nil {
			// 半帧：视为结束。
			return nil
		}
		if idx >= from {
			var res pb.ScanResult
			if err := proto.Unmarshal(body, &res); err != nil {
				// 单帧损坏不应中断其后的完整帧；跳过后续由调用方决定，这里保守结束。
				return nil
			}
			if err := fn(&res); err != nil {
				return err
			}
		}
		idx++
	}
}

// Count 返回当前已追加的帧数（仅写模式可靠）。
func (w *resultWAL) Count() int {
	if w == nil {
		return 0
	}
	return w.count
}

// Path 返回 WAL 文件路径。
func (w *resultWAL) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

// Close 关闭底层文件句柄（不删除文件）。
func (w *resultWAL) Close() error {
	if w == nil || w.file == nil {
		return nil
	}
	if w.w != nil {
		if err := w.w.Flush(); err != nil {
			_ = w.file.Close()
			return err
		}
	}
	return w.file.Close()
}

// Discard 关闭并删除 WAL 文件（任务尝试成功收敛后调用）。
func (w *resultWAL) Discard() error {
	if w == nil {
		return nil
	}
	path := w.path
	var err error
	if w.file != nil {
		err = w.Close()
	}
	if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return rmErr
	}
	return err
}
