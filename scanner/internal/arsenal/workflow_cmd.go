package arsenal

import (
	"flag"
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
)

// HandleWorkflowCommand 处理 `dddd workflow <subcommand>` 命令。
func HandleWorkflowCommand(args []string) {
	if len(args) == 0 {
		workflowUsage()
		return
	}

	MustOpenDB("")
	SeedFromEmbed()

	switch args[0] {
	case "list":
		workflowList(args[1:])
	case "add":
		workflowAdd(args[1:])
	case "del":
		workflowDel(args[1:])
	case "import":
		workflowImportCmd(args[1:])
	case "export":
		workflowExportCmd()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: workflow %s\n", args[0])
		workflowUsage()
		os.Exit(1)
	}
}

func workflowUsage() {
	fmt.Println(`用法: dddd workflow <子命令>

子命令:
  list      列出映射 (--product 过滤)
  add       添加映射: dddd workflow add <产品名> <POC名> <类型(root/dir/base)>
  del       删除映射: dddd workflow del <产品名> <POC名>
  import    从 YAML 导入: dddd workflow import <文件路径>
  export    导出为 YAML 格式`)
}

func workflowList(args []string) {
	fs := flag.NewFlagSet("workflow list", flag.ExitOnError)
	product := fs.String("product", "", "按产品名过滤")
	limit := fs.Int("limit", 50, "每页条数")
	offset := fs.Int("offset", 0, "偏移量")
	_ = fs.Parse(args)

	workflows, total, err := ListWorkflows(*product, *limit, *offset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "查询失败: %v\n", err)
		os.Exit(1)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"产品名", "POC 名称", "匹配类型", "启用"})
	table.SetAutoWrapText(false)

	for _, w := range workflows {
		enabled := "✅"
		if !w.Enabled {
			enabled = "⬜"
		}
		table.Append([]string{w.ProductName, w.PocName, w.MatchType, enabled})
	}
	table.Render()
	fmt.Printf("  共 %d 条 (显示 %d-%d)\n", total, *offset+1, *offset+len(workflows))
}

func workflowAdd(args []string) {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "用法: dddd workflow add <产品名> <POC名> <类型(root/dir/base/dir-fallback)>")
		os.Exit(1)
	}
	product := args[0]
	pocName := args[1]
	matchType := args[2]

	w := &Workflow{
		ProductName: product,
		PocName:     pocName,
		MatchType:   matchType,
		Enabled:     true,
	}
	created, err := AddWorkflow(w)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 添加失败: %v\n", err)
		os.Exit(1)
	}
	if created {
		fmt.Printf("  ✅ 映射已创建: %s → %s (类型: %s)\n", product, pocName, matchType)
	} else {
		fmt.Println("  ℹ️  该映射已存在")
	}
}

func workflowDel(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: dddd workflow del <产品名> <POC名>")
		os.Exit(1)
	}
	affected, err := DeleteWorkflow(args[0], args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 删除失败: %v\n", err)
		os.Exit(1)
	}
	if affected > 0 {
		fmt.Printf("  ✅ 已删除 %d 条映射\n", affected)
	} else {
		fmt.Println("  ℹ️  未找到匹配的映射")
	}
}

func workflowImportCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: dddd workflow import <yaml文件路径>")
		os.Exit(1)
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 读取文件失败: %v\n", err)
		os.Exit(1)
	}
	added, skipped, err := ImportWorkflowYAML(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 导入失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  ✅ 导入完成: 新增 %d, 跳过 %d\n", added, skipped)
}

func workflowExportCmd() {
	data, err := ExportWorkflowYAML()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 导出失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(string(data))
}
