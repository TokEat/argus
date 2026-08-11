package engine

import (
	"dddd/scanner/internal/finger"
	"dddd/scanner/internal/scanner/protocol"
	"dddd/scanner/internal/scanner/web"
	"dddd/scanner/structs"
	"embed"
)

func currentPipelineIPPortMap(ctx *ScanContext) map[string]string {
	return ctx.IPPortMap
}

func currentWebRuntime(ctx *ScanContext, emit func(structs.OutputMessage)) *web.Runtime {
	return web.NewRuntime(
		ctx.URLMap,
		&ctx.URLMapLock,
		ctx.IPDomainMap,
		ctx.BodyHMap,
		ctx.HeaderHMap,
		currentPipelineDirDB(ctx),
		currentPipelineFingerprintDB(ctx),
		currentPipelineWorkflowDB(ctx),
		ctx.DirFallbackResultMap,
		&ctx.DirFallbackResultMapLock,
		emit,
	)
}

func currentFingerRuntime(ctx *ScanContext, emit func(structs.OutputMessage)) *finger.Runtime {
	return finger.NewRuntime(
		ctx.IPPortMap,
		ctx.URLMap,
		ctx.ResultMap,
		ctx.BannerHMap,
		ctx.BodyHMap,
		ctx.HeaderHMap,
		currentPipelineFingerprintDB(ctx),
		emit,
	)
}

func currentProtocolRuntime(ctx *ScanContext, emit func(structs.OutputMessage)) *protocol.Runtime {
	return protocol.NewRuntime(
		ctx.IPPortMap,
		&ctx.IPPortMapLock,
		ctx.BannerHMap,
		emit,
	)
}

func currentPipelineURLMap(ctx *ScanContext) map[string]URLEntity {
	return ctx.URLMap
}

func currentPipelineDirDB(ctx *ScanContext) map[string][]string {
	if ctx.knowledge != nil {
		return ctx.knowledge.dirDB
	}
	return ctx.DirDB
}

func currentPipelineFingerprintDB(ctx *ScanContext) []FingerPEntity {
	if ctx.knowledge != nil {
		return ctx.knowledge.fingerprintDB
	}
	return ctx.FingerprintDB
}

func currentPipelineResultMap(ctx *ScanContext) map[string][]string {
	return ctx.ResultMap
}

func setPipelineResultMap(ctx *ScanContext, resultMap map[string][]string) {
	ctx.ResultMap = resultMap
}

func currentPipelineDirFallbackResultMap(ctx *ScanContext) map[string][]string {
	return ctx.DirFallbackResultMap
}

func currentPipelineWorkflowDB(ctx *ScanContext) map[string]structs.WorkFlowEntity {
	if ctx.knowledge != nil {
		return ctx.knowledge.workflowDB
	}
	return ctx.WorkFlowDB
}

func currentPipelineEmbedPocs(ctx *ScanContext) embed.FS {
	return ctx.EmbedPocs
}
