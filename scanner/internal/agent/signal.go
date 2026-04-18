package agent

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
)

// StartSpotTerminationListener 监听云厂商竞价实例(Spot Instance)的中断通知。
// 以阿里云为例，可以通过轮询 meta-data 接口获取释放时间。
func (w *Worker) StartSpotTerminationListener() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			// 阿里云 Spot 实例释放前5分钟元数据会被下发
			resp, err := http.Get("http://100.100.100.200/latest/meta-data/instance/spot/termination-time")
			if err != nil {
				// 网络错误或不在阿里云环境
				continue
			}

			if resp.StatusCode == 200 {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				terminationTime := strings.TrimSpace(string(body))
				if terminationTime != "" {
					log.Printf("[EMERGENCY] Spot instance is scheduled for termination at %s. Triggering Emergency Dump!", terminationTime)

					// 触发紧急回传，将此时内存里的上下文数据或残余队列数据立刻提交
					_, rpcErr := w.client.EmergencyDump(context.Background(), &pb.EmergencyReq{
						AgentId: w.agentID,
					})
					if rpcErr != nil {
						log.Printf("Failed to transmit emergency dump: %v", rpcErr)
					}

					// 我们只有 5 分钟时间，完成回传后即可退出或等待系统 kill
					log.Println("Emergency Dump completed. Shutting down worker gracefully...")
					time.Sleep(3 * time.Second)

					// 通知后优雅退出本进程，外部如有 Systemd 会被拉起，但马上虚拟机就被销毁了
					// os.Exit(0)
					return
				}
			} else {
				resp.Body.Close()
			}
		}
	}()
}
