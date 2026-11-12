// Command arsenal-import 从公网优秀项目收集指纹与 POC，深度语义去重后融入
// scanner/common/config/，并输出每阶段可审阅的报告。灌库（build_seed_db +
// --seed-from-db）由阶段 8 单独执行。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type options struct {
	workdir string
	cache   string
	config  string
	// 各阶段阈值
	nearDupPoc     float64
	nearDupFinger  float64
	wireConfidence float64
	activeFPCap    int
	// 阶段开关
	yes bool
}

func main() {
	var opt options
	fs := flag.NewFlagSet("arsenal-import", flag.ExitOnError)
	fs.StringVar(&opt.workdir, "workdir", "data/arsenal-import", "阶段产物输出目录")
	fs.StringVar(&opt.cache, "cache", filepath.Join(os.Getenv("HOME"), ".cache", "argus-import"), "源仓库缓存目录")
	fs.StringVar(&opt.config, "config", filepath.Join("scanner", "common", "config"), "目标配置目录")
	fs.Float64Var(&opt.nearDupPoc, "poc-near-dup", 0.85, "POC 近重复 Jaccard 阈值")
	fs.Float64Var(&opt.nearDupFinger, "finger-near-dup", 0.90, "指纹近重复 Jaccard 阈值")
	fs.Float64Var(&opt.wireConfidence, "wire-confidence", 0.80, "workflow 自动挂载最低置信度")
	fs.IntVar(&opt.activeFPCap, "active-fp-cap", 7, "主动指纹 safe 名额上限（auto-safe 每租户硬上限 8，shiro 已占 1）")
	fs.BoolVar(&opt.yes, "yes", false, "跳过交互确认（阶段内连续执行）")
	_ = fs.Parse(os.Args[1:])

	if fs.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	if err := os.MkdirAll(opt.workdir, 0o755); err != nil {
		fatal(err)
	}

	cmd := fs.Arg(0)
	var err error
	switch cmd {
	case "fetch":
		err = runFetch(&opt)
	case "convert":
		err = runConvert(&opt)
	case "select":
		err = runSelect(&opt)
	case "dedup":
		err = runDedup(&opt)
	case "wire":
		err = runWire(&opt)
	case "merge":
		err = runMerge(&opt)
	case "validate":
		err = runValidate(&opt)
	case "prune":
		err = runPrune(&opt)
	case "report":
		err = runReport(&opt)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `用法: arsenal-import [全局选项] <子命令>

子命令（按序执行，产物写入 --workdir）:
  fetch      克隆/更新源仓库，记录 commit SHA 与 license
  convert    归一化各源格式为候选规则（nuclei/afrog/xray→POC，tech→主动指纹，fofa→被动指纹）
  select     精选过滤（severity/tag/目录/可转换性门控）
  dedup      深度语义去重（对现有库 + 批内双向）
  wire       workflow.yaml 自动挂载 + 置信度报告
  merge      备份并合并入 --config 目录
  validate   nuclei 严格解析 + 主动指纹 Inspect 校验
  prune      移除 validate 判失败的 POC 并清理 workflow 引用
  report     聚合各阶段产物为总报告
`)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "arsenal-import: %v\n", err)
	os.Exit(1)
}
