package arsenal

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/olekukonko/tablewriter"
)

// HandlePocCommand 处理 `argus poc <subcommand>` 命令。
func HandlePocCommand(args []string) {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		pocUsage()
		return
	}

	MustOpenDB("")
	SeedFromEmbed()

	switch args[0] {
	case "list":
		pocList(args[1:])
	case "count":
		pocCount()
	case "show":
		pocShow(args[1:])
	case "add":
		pocAdd(args[1:])
	case "del":
		pocDel(args[1:])
	case "validate":
		pocValidate(args[1:])
	case "import":
		pocImportCmd(args[1:])
	case "export":
		pocExportCmd(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: poc %s\n", args[0])
		pocUsage()
		os.Exit(1)
	}
}

func pocUsage() {
	fmt.Println(`Argus CLI 规则库管理

用法: argus poc <子命令>

子命令:
  list      列出 POC (--name, --severity 过滤)
  count     统计 POC 数量
  show      查看 POC 详情: argus poc show <名称>
  add       添加 POC: argus poc add <yaml文件>
  del       删除 POC: argus poc del <名称>
  validate  校验 POC: argus poc validate <yaml文件>
  import    批量导入目录: argus poc import <目录>
  export    导出所有 POC: argus poc export --dir <输出目录>`)
}

func pocList(args []string) {
	fs := flag.NewFlagSet("poc list", flag.ExitOnError)
	name := fs.String("name", "", "按名称搜索")
	severity := fs.String("severity", "", "按严重度过滤")
	source := fs.String("source", "", "按来源过滤")
	limit := fs.Int("limit", 30, "每页条数")
	offset := fs.Int("offset", 0, "偏移量")
	_ = fs.Parse(args)

	pocs, total, err := ListPocs(*name, *severity, *source, false, *limit, *offset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "查询失败: %v\n", err)
		os.Exit(1)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"名称", "漏洞等级", "执行类别", "执行风险", "标签", "来源", "启用"})
	table.SetAutoWrapText(false)

	for _, p := range pocs {
		tags := p.Tags
		if len(tags) > 30 {
			tags = tags[:27] + "..."
		}
		enabled := "✅"
		if !p.Enabled {
			enabled = "⬜"
		}
		table.Append([]string{p.Name, p.Severity, p.ExecutionClass, p.RiskLevel, tags, p.Source, enabled})
	}
	table.Render()
	fmt.Printf("  共 %d 个 (显示 %d-%d)\n", total, *offset+1, *offset+len(pocs))
}

func pocCount() {
	total, bySeverity := CountPocs()
	fmt.Printf("POC 总数: %d\n", total)
	for sev, cnt := range bySeverity {
		fmt.Printf("  %s: %d\n", sev, cnt)
	}
}

func pocShow(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: argus poc show <名称>")
		os.Exit(1)
	}
	poc, err := GetPocByName(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 未找到 POC: %s\n", args[0])
		os.Exit(1)
	}
	fmt.Printf("# Name:     %s\n", poc.Name)
	fmt.Printf("# Severity: %s\n", poc.Severity)
	fmt.Printf("# Execution: %s\n", poc.ExecutionClass)
	fmt.Printf("# Risk:     %s\n", poc.RiskLevel)
	fmt.Printf("# Tags:     %s\n", poc.Tags)
	fmt.Printf("# Author:   %s\n", poc.Author)
	fmt.Printf("# Source:    %s\n", poc.Source)
	fmt.Printf("# Hash:     %s\n", poc.ContentHash)
	fmt.Println("---")
	fmt.Println(poc.Content)
}

func pocAdd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: argus poc add <yaml文件>")
		os.Exit(1)
	}
	content, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 读取文件失败: %v\n", err)
		os.Exit(1)
	}
	name, created, err := ImportPocFile(content, args[0], "user")
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 添加失败: %v\n", err)
		os.Exit(1)
	}
	if created {
		fmt.Printf("  ✅ POC 已添加: %s\n", name)
	} else {
		fmt.Printf("  ℹ️  POC 已更新: %s\n", name)
	}
}

func pocDel(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: argus poc del <名称>")
		os.Exit(1)
	}
	affected, err := DeletePoc(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 删除失败: %v\n", err)
		os.Exit(1)
	}
	if affected > 0 {
		fmt.Printf("  ✅ 已删除 POC: %s\n", args[0])
	} else {
		fmt.Println("  ℹ️  未找到匹配的 POC")
	}
}

func pocValidate(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: argus poc validate <yaml文件>")
		os.Exit(1)
	}
	content, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 读取文件失败: %v\n", err)
		os.Exit(1)
	}

	// 基础 YAML 校验
	meta := parsePocMeta(content)
	if meta.id == "" {
		fmt.Fprintln(os.Stderr, "❌ 缺少 id 字段")
		os.Exit(1)
	}
	fmt.Println("  ✅ YAML 语法正确")
	fmt.Printf("  ℹ️  ID: %s | Severity: %s | Tags: %s\n", meta.id, meta.severity, meta.tags)
}

func pocImportCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: argus poc import <目录路径>")
		os.Exit(1)
	}
	dir := args[0]
	var added, skipped int

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".yaml") {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			skipped++
			return nil
		}
		_, created, addErr := ImportPocFile(content, info.Name(), "user")
		if addErr != nil {
			skipped++
			return nil
		}
		if created {
			added++
		} else {
			skipped++
		}
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 遍历目录失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  ✅ 导入完成: 新增 %d, 跳过/更新 %d\n", added, skipped)
}

func pocExportCmd(args []string) {
	fs := flag.NewFlagSet("poc export", flag.ExitOnError)
	dir := fs.String("dir", "exported_pocs", "输出目录")
	_ = fs.Parse(args)

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 创建目录失败: %v\n", err)
		os.Exit(1)
	}

	pocs, err := GetAllEnabledPocs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 查询失败: %v\n", err)
		os.Exit(1)
	}

	for _, p := range pocs {
		outPath := filepath.Join(*dir, p.FileName)
		if err := os.WriteFile(outPath, []byte(p.Content), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️ 写入失败: %s: %v\n", p.FileName, err)
			continue
		}
	}
	fmt.Printf("  ✅ 已导出 %d 个 POC 到 %s/\n", len(pocs), *dir)
}
