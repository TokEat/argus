//go:build tools

package main

import (
	"crypto/md5"
	"fmt"
	"log"
	"os"

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
	tdb, err := gorm.Open(sqlite.Open("../data/server-dict.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("open target sqlite: %v", err)
	}
	tdb.AutoMigrate(&Arsenal{})

	importYAML := func(typ, fileName, filePath string) {
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("SKIP %s: %v", filePath, err)
			return
		}
		content := string(data)
		hash := fmt.Sprintf("%x", md5.Sum(data))
		// ID must match BuildTenantArsenalID("default", typ, fileName) = CanonicalArsenalType(typ) + "_" + fileName
		canonical := typ
		switch typ {
		case "finger", "fingerprint":
			canonical = "finger"
		}
		id := canonical + "_" + fileName
		a := Arsenal{
			ID:       id,
			TenantID: "default",
			Type:     typ,
			FileName: fileName,
			Content:  content,
			Hash:     hash,
			State:    "Approved",
			Version:  1,
		}
		if err := tdb.Create(&a).Error; err != nil {
			log.Printf("ERROR creating %s: %v", id, err)
		} else {
			log.Printf("OK %s (%d bytes)", id, len(content))
		}
	}

	cfgDir := "../scanner/common/config"
	importYAML("finger", "finger.yaml", cfgDir+"/finger.yaml")
	importYAML("workflow", "workflow.yaml", cfgDir+"/workflow.yaml")
	importYAML("dir", "dir.yaml", cfgDir+"/dir.yaml")
	importYAML("apiconfig", "api-config.yaml", cfgDir+"/api-config.yaml")
	log.Println("Done! Output: data/server-dict.db")
}
