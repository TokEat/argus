//go:build tools

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type Arsenal struct {
	ID       string `gorm:"primaryKey"`
	TenantID string `gorm:"default:'default';index"`
	Type     string `gorm:"index"`
	FileName string `gorm:"index"`
	Content  string `gorm:"type:text"`
	Hash     string
	State    string `gorm:"default:'Draft';index"`
	Version  int    `gorm:"default:1"`
}

func main() {
	sdb, err := gorm.Open(sqlite.Open("../data/arsenal.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("open source sqlite: %v", err)
	}

	tdb, err := gorm.Open(sqlite.Open("../data/server-arsenal.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("open target sqlite: %v", err)
	}
	tdb.AutoMigrate(&Arsenal{})

	shortHash := func(s string) string {
		h := sha256.Sum256([]byte(s))
		return fmt.Sprintf("%x", h[:8])
	}

	fullHash := func(s string) string {
		h := sha256.Sum256([]byte(s))
		return fmt.Sprintf("%x", h[:])
	}

	importRow := func(id, typ, fileName, content string) {
		a := Arsenal{
			ID:       id,
			TenantID: "default",
			Type:     typ,
			FileName: fileName,
			Content:  content,
			Hash:     fullHash(content),
			State:    "Approved",
			Version:  1,
		}
		if err := tdb.Create(&a).Error; err != nil {
			log.Printf("skip duplicate: %s", id)
		}
	}

	// 1. Fingerprints
	type Fingerprint struct {
		ProductName string
		RuleExpr    string
		Category    string
		Tags        string
	}
	var fingers []Fingerprint
	sdb.Table("fingerprints").Find(&fingers)
	for _, f := range fingers {
		b, _ := json.Marshal(map[string]string{
			"product": f.ProductName, "rule": f.RuleExpr,
			"category": f.Category, "tags": f.Tags,
		})
		content := string(b)
		id := "finger_" + shortHash(content)
		importRow(id, "fingerprint", f.ProductName+".json", content)
	}
	log.Printf("Fingerprints: %d", len(fingers))

	// 2. POCs
	type Poc struct {
		Name        string
		FileName    string
		Content     string
		ContentHash string
		Severity    string
		Tags        string
		Author      string
		Description string
	}
	var pocs []Poc
	sdb.Table("pocs").Find(&pocs)
	for _, p := range pocs {
		id := "poc_" + shortHash(p.Name)
		importRow(id, "poc", p.FileName, p.Content)
	}
	log.Printf("POCs: %d", len(pocs))

	// 3. Workflows
	type Workflow struct {
		ProductName string
		PocName     string
		MatchType   string
	}
	var workflows []Workflow
	sdb.Table("workflows").Find(&workflows)
	for _, w := range workflows {
		raw := fmt.Sprintf("%s|%s|%s", w.ProductName, w.PocName, w.MatchType)
		id := "wf_" + shortHash(raw)
		b, _ := json.Marshal(map[string]string{
			"product": w.ProductName, "poc": w.PocName, "match_type": w.MatchType,
		})
		importRow(id, "workflow", w.ProductName+".json", string(b))
	}
	log.Printf("Workflows: %d", len(workflows))

	// 4. DirProbes
	type DirProbe struct {
		Path        string
		ProductName string
	}
	var dirs []DirProbe
	sdb.Table("dir_probes").Find(&dirs)
	for _, d := range dirs {
		raw := d.ProductName + "|" + d.Path
		id := "dir_" + shortHash(raw)
		b, _ := json.Marshal(map[string]string{"product": d.ProductName, "path": d.Path})
		importRow(id, "dir", d.ProductName+".json", string(b))
	}
	log.Printf("DirProbes: %d", len(dirs))

	log.Println("Done! Output: data/server-arsenal.db")
}
