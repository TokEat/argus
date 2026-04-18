package main

import (
	"dddd/scanner/internal/arsenal"
	"dddd/scanner/internal/config"
	"dddd/scanner/internal/engine"
	"log"
	"os"
)

func main() {
	// 子命令分发：finger / poc / workflow
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "finger":
			arsenal.HandleFingerCommand(os.Args[2:])
			return
		case "poc":
			arsenal.HandlePocCommand(os.Args[2:])
			return
		case "workflow":
			arsenal.HandleWorkflowCommand(os.Args[2:])
			return
		}
	}

	// 默认行为：扫描（完全向后兼容）
	ctx, err := config.InitCLI()
	if err != nil {
		log.Fatalf("cli init failed: %v", err)
	}
	defer ctx.Close()

	if err := engine.RunTask(ctx); err != nil {
		log.Fatalf("pipeline failed: %v", err)
	}
}
