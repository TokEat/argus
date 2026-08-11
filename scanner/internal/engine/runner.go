package engine

import (
	"context"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/structs"
)

// RunTask executes the unified scan entrypoint for both CLI and agent modes.
func RunTask(ctx *ScanContext) error {
	pipeline := &Pipeline{}
	return pipeline.Run(ctx)
}

// NewScanContextFromLegacyGlobals builds a ScanContext from the current legacy
// global runtime. This is used by the standalone CLI while the flag parsing and
// bootstrap path still lives in common.Flag().
func NewScanContextFromLegacyGlobals(taskID string) (*ScanContext, error) {
	if structs.GlobalHttpBodyHMap == nil || structs.GlobalHttpHeaderHMap == nil || structs.GlobalBannerHMap == nil {
		return nil, fmt.Errorf("legacy runtime caches are not initialized")
	}

	ctx, cancel := context.WithCancel(context.Background())

	sc := &ScanContext{
		TaskID: taskID,
		Config: Config(structs.GlobalConfig),

		IPPortMap:            structs.GlobalIPPortMap,
		IPDomainMap:          structs.GlobalIPDomainMap,
		URLMap:               toEngineURLMap(structs.GlobalURLMap),
		httpURLVisits:        make(map[string]struct{}),
		ResultMap:            structs.GlobalResultMap,
		DirFallbackResultMap: structs.DirFallbackResultMap,
		GoPocsResults:        toEngineGoPocResults(structs.GoPocsResults),

		BannerHMap: structs.GlobalBannerHMap,
		BodyHMap:   structs.GlobalHttpBodyHMap,
		HeaderHMap: structs.GlobalHttpHeaderHMap,

		EmbedPocs:     structs.GlobalEmbedPocs,
		FingerprintDB: toEngineFingerDB(structs.FingerprintDB),
		WorkFlowDB:    toEngineWorkflowDB(structs.WorkFlowDB),
		DirDB:         cloneDirDB(structs.DirDB),
		AddScanNum:    structs.AddScanNum,
		AddScanEnd:    structs.AddScanEnd,

		Ctx:    ctx,
		Cancel: cancel,
	}

	return sc, nil
}
