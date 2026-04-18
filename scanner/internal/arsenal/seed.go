package arsenal

import (
	commoncfg "dddd/scanner/common"
	"log"
)

// SeedFromEmbed 从编译时内嵌的 YAML 数据自动导入到数据库。
// 仅在数据库为空时执行。
func SeedFromEmbed() {
	if IsDBReady() {
		return
	}

	log.Println("[Arsenal] 首次运行，正在导入内置规则库...")

	// 1. 导入指纹
	added, skipped, err := ImportFingerYAML([]byte(commoncfg.EmbedFingerData), "builtin")
	if err != nil {
		log.Printf("[Arsenal] 指纹导入失败: %v", err)
	} else {
		log.Printf("[Arsenal] 指纹: 新增 %d, 跳过 %d", added, skipped)
	}

	// 2. 导入 Workflow
	added, skipped, err = ImportWorkflowYAML([]byte(commoncfg.EmbedWorkFlowData))
	if err != nil {
		log.Printf("[Arsenal] Workflow 导入失败: %v", err)
	} else {
		log.Printf("[Arsenal] Workflow: 新增 %d, 跳过 %d", added, skipped)
	}

	// 3. 导入主动探测路径
	added, skipped, err = ImportDirYAML([]byte(commoncfg.EmbedDirDBData))
	if err != nil {
		log.Printf("[Arsenal] Dir 探测路径导入失败: %v", err)
	} else {
		log.Printf("[Arsenal] Dir: 新增 %d, 跳过 %d", added, skipped)
	}

	// 4. 导入 Nuclei POC
	added, skipped, err = ImportPocsFromFS(commoncfg.EmbedNucleiPocs, "builtin")
	if err != nil {
		log.Printf("[Arsenal] POC 导入失败: %v", err)
	} else {
		log.Printf("[Arsenal] POC: 新增 %d, 跳过 %d", added, skipped)
	}

	log.Println("[Arsenal] ✅ 内置规则库导入完成")
}
