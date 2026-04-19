package main

import (
	"fmt"
	"github.com/user/dddd-server/internal/db"
)

func main() {
	db.InitDB("")
	var arsenals []db.Arsenal
	db.DB.Where("type IN ?", db.ArsenalTypeAliases("poc")).Find(&arsenals)
	fmt.Printf("Total POCs in DB: %d\n", len(arsenals))
    if len(arsenals) > 0 {
        fmt.Printf("First POC FileName: %s, State: %s\n", arsenals[0].FileName, arsenals[0].State)
    }

    var dicts []db.WorkflowRule
	db.DB.Find(&dicts)
	fmt.Printf("Total Workflows in DB: %d\n", len(dicts))

    var fps []db.FingerprintRule
	db.DB.Find(&fps)
	fmt.Printf("Total Fingerprints in DB: %d\n", len(fps))
}
