package arsenal

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"
)

// HandleFingerCommand 处理 `dddd finger <subcommand>` 命令。
func HandleFingerCommand(args []string) {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fingerUsage()
		return
	}

	MustOpenDB("")
	SeedFromEmbed()

	switch args[0] {
	case "list":
		fingerList(args[1:])
	case "count":
		fingerCount()
	case "stats":
		fingerStats()
	case "add":
		fingerAdd(args[1:])
	case "del":
		fingerDel(args[1:])
	case "test":
		fingerTest(args[1:])
	case "import":
		fingerImport(args[1:])
	case "export":
		fingerExport()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: finger %s\n", args[0])
		fingerUsage()
		os.Exit(1)
	}
}

func fingerUsage() {
	fmt.Println(`Argus CLI 规则库管理

用法: dddd finger <子命令>

子命令:
  list     列出指纹规则 (--product, --category, --source 过滤)
  count    统计指纹数量
  stats    显示统计信息
  add      添加指纹规则: dddd finger add <产品名> <规则表达式>
  del      删除指纹规则: dddd finger del <产品名> <规则表达式>
  test     校验规则语法: dddd finger test <规则表达式>
  import   从 YAML 导入: dddd finger import <文件路径>
  export   导出为 YAML 格式`)
}

func fingerList(args []string) {
	fs := flag.NewFlagSet("finger list", flag.ExitOnError)
	product := fs.String("product", "", "按产品名过滤")
	category := fs.String("category", "", "按分类过滤 (web/service/iot)")
	source := fs.String("source", "", "按来源过滤 (builtin/user)")
	limit := fs.Int("limit", 30, "每页条数")
	offset := fs.Int("offset", 0, "偏移量")
	_ = fs.Parse(args)

	fingers, total, err := ListFingerprints(*product, *category, *source, false, *limit, *offset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "查询失败: %v\n", err)
		os.Exit(1)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"产品名", "规则", "分类", "来源", "启用"})
	table.SetAutoWrapText(false)
	table.SetColWidth(60)

	for _, f := range fingers {
		rule := f.RuleExpr
		if len(rule) > 60 {
			rule = rule[:57] + "..."
		}
		enabled := "✅"
		if !f.Enabled {
			enabled = "⬜"
		}
		table.Append([]string{f.ProductName, rule, f.Category, f.Source, enabled})
	}
	table.Render()
	fmt.Printf("  共 %d 条 (显示 %d-%d)\n", total, *offset+1, *offset+len(fingers))
}

func fingerCount() {
	total, bySource := CountFingerprints()
	fmt.Printf("指纹总数: %d\n", total)
	for src, cnt := range bySource {
		fmt.Printf("  %s: %d\n", src, cnt)
	}
}

func fingerStats() {
	total, bySource := CountFingerprints()
	pocTotal, bySeverity := CountPocs()
	wfCount := CountWorkflows()

	fmt.Println("📊 指纹库统计：")
	fmt.Printf("   总数: %d 条\n", total)
	for src, cnt := range bySource {
		fmt.Printf("   %s: %d 条\n", src, cnt)
	}

	fmt.Println("\n📊 POC 库统计：")
	fmt.Printf("   总数: %d 个\n", pocTotal)
	for sev, cnt := range bySeverity {
		fmt.Printf("   %s: %d\n", sev, cnt)
	}

	fmt.Println("\n📊 Workflow 映射：")
	fmt.Printf("   总映射: %d 条\n", wfCount)
}

func fingerAdd(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: dddd finger add <产品名> <规则表达式>")
		os.Exit(1)
	}
	product := args[0]
	rule := strings.Join(args[1:], " ")

	// 语法校验
	if err := ValidateFingerRule(rule); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 规则语法错误: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("  ✅ 规则语法校验通过")

	f := &Fingerprint{
		ProductName: product,
		RuleExpr:    rule,
		Category:    "web",
		Source:      "user",
		Enabled:     true,
	}
	created, err := AddFingerprint(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 添加失败: %v\n", err)
		os.Exit(1)
	}
	if created {
		fmt.Println("  ✅ 已添加到本地弹药库")
		fmt.Printf("     Product: %s\n", product)
		fmt.Printf("     Rule:    %s\n", rule)
		fmt.Printf("     Source:  user\n")
	} else {
		fmt.Println("  ℹ️  该规则已存在，已跳过")
	}
}

func fingerDel(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: dddd finger del <产品名> <规则表达式>")
		os.Exit(1)
	}
	product := args[0]
	rule := strings.Join(args[1:], " ")

	affected, err := DeleteFingerprint(product, rule)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 删除失败: %v\n", err)
		os.Exit(1)
	}
	if affected > 0 {
		fmt.Printf("  ✅ 已删除 %d 条规则\n", affected)
	} else {
		fmt.Println("  ℹ️  未找到匹配的规则")
	}
}

func fingerTest(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: dddd finger test <规则表达式>")
		os.Exit(1)
	}
	rule := strings.Join(args, " ")

	if err := ValidateFingerRule(rule); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 语法错误: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("  ✅ 规则语法正确")
}

func fingerImport(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: dddd finger import <yaml文件路径>")
		os.Exit(1)
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 读取文件失败: %v\n", err)
		os.Exit(1)
	}
	added, skipped, err := ImportFingerYAML(data, "user")
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 导入失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  ✅ 导入完成: 新增 %d, 跳过 %d\n", added, skipped)
}

func fingerExport() {
	data, err := ExportFingerYAML()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 导出失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(string(data))
}
