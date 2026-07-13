package api

import "github.com/gin-gonic/gin"

func registerAPIV1Routes(api *gin.RouterGroup) {
	// JWT 签发
	api.POST("/auth/login", authLogin)

	// WebSocket 入口
	api.GET("/ws", HandleWS)

	// Dashboard 统计数据
	api.GET("/stats", getStats)

	// 项目 CRUD
	api.GET("/projects", getProjects)
	api.POST("/projects", createProject)
	api.PUT("/projects/:id", updateProject)
	api.DELETE("/projects/:id", deleteProject)
	api.GET("/projects/:id/stats", getProjectStats)
	api.GET("/projects/:id/members", getProjectMembers)
	api.PUT("/projects/:id/members", updateProjectMembers)

	// 任务 CRUD
	api.GET("/tasks", getTasks)
	api.GET("/tasks/:id", getTaskDetail)
	api.POST("/tasks/preview-selector", previewTaskSelector)
	api.POST("/tasks/validate-targets", validateTargets)
	api.POST("/tasks", createTask)
	api.DELETE("/tasks/:id", deleteTask)
	api.POST("/tasks/:id/cancel", cancelTask)
	api.POST("/tasks/:id/pause", pauseTask)
	api.POST("/tasks/:id/resume", resumeTask)
	api.POST("/tasks/:id/append", appendTargets) // 动态追加目标

	// 队列监控
	api.GET("/queue/depth", getQueueDepth)

	// 漏洞资产与关联画像
	api.GET("/vulns", getVulns)
	api.GET("/assets", getAssets)
	api.GET("/fingerprints", getFingerprints)
	api.GET("/profiles", getProfiles)
	api.GET("/poc-rules", listPocRules)
	api.GET("/exploits", listExploitRules)
	api.GET("/exploits/audits", listExploitAudits)
	api.POST("/exploits/source/validate", validateSourceExploit)
	api.POST("/exploits/source/dry-run", dryRunSourceExploit)
	api.POST("/exploits/source/debug", debugSourceExploit)
	api.POST("/exploits/batch/approve", batchApproveExploitRules)
	api.POST("/exploits/batch/deprecate", batchDeprecateExploitRules)
	api.GET("/exploits/:id/risk-waiver", getExploitRiskWaiver)
	api.POST("/exploits/:id/risk-waiver", upsertExploitRiskWaiver)
	api.PUT("/exploits/:id/risk-waiver", upsertExploitRiskWaiver)
	api.DELETE("/exploits/:id/risk-waiver", deleteExploitRiskWaiver)
	api.POST("/exploits/:id/approve", approveExploitRule)
	api.POST("/exploits/:id/deprecate", deprecateExploitRule)
	api.POST("/exploits/:id/dry-run", dryRunExploit)
	api.POST("/exploits/:id/debug", debugExploit)
	api.DELETE("/exploits/:id", deleteExploitRule)
	api.GET("/vulns/:id/exploit-candidates", getExploitCandidatesForVuln)
	api.GET("/assets/:id/exploit-candidates", getExploitCandidatesForAsset)

	// EXP 执行管理
	api.POST("/exploit-runs", createExploitRun)
	api.GET("/exploit-runs", listExploitRuns)
	api.GET("/exploit-runs/:id", getExploitRun)
	api.POST("/exploit-runs/:id/cancel", cancelExploitRun)
	api.POST("/exploit-runs/:id/cleanup", cleanupExploitRun)
	api.GET("/exploit-artifacts/:id", getExploitArtifact)

	// 战报输出引擎
	api.GET("/reports/export/vulns", exportVulns)
	api.GET("/reports/export/assets", exportAssets)
	api.GET("/reports/export/fingerprints", exportFingerprints)

	// Agent 节点
	api.GET("/nodes", getNodes)
	api.DELETE("/nodes/:id", deleteNode)
	api.POST("/nodes/:id/revoke-token", revokeNodeToken)
	api.POST("/nodes/clean", cleanOfflineNodes)
	api.GET("/agents/:id/commands", getAgentCommands)
	api.GET("/agents/:id/pyenv", getAgentPyenv)
	api.POST("/agents/:id/pyenv/install", installAgentPyenvRequirements)
	api.GET("/agents/:id/pyenv/jobs/:job_id", getAgentPyenvJob)

	// MCP support APIs for Codex/agent rule authoring loops.
	api.GET("/mcp/resources/argus-mcp/quickstart", mcpArgusMCPQuickstart)
	api.GET("/mcp/resources/argus-mcp/tool-guide", mcpArgusMCPToolGuide)
	api.GET("/mcp/resources/fingerprint/spec", mcpFingerprintSpec)
	api.GET("/mcp/resources/fingerprint/template", mcpFingerprintTemplate)
	api.GET("/mcp/resources/poc/spec", mcpPOCSpec)
	api.GET("/mcp/resources/pyexp/spec", mcpPyexpSpec)
	api.GET("/mcp/resources/pyexp/template", mcpPyexpTemplate)
	api.GET("/mcp/resources/poc/template", mcpPOCTemplate)
	api.GET("/mcp/resources/workflow/spec", mcpWorkflowSpec)
	api.GET("/mcp/resources/workflow/template", mcpWorkflowTemplate)
	api.GET("/mcp/resources/examples/fingerprint-poc-workflow", mcpFullChainExample)
	api.POST("/mcp/tools/poc/debug", mcpPOCDebug)
	api.POST("/mcp/tools/poc/save-draft", mcpPOCSaveDraft)
	api.POST("/mcp/tools/agent/python-run", mcpAgentPythonRun)
	api.POST("/mcp/tools/rule/context", mcpRuleContext)
	api.POST("/mcp/tools/rule/debug", mcpRuleDebug)
	api.POST("/mcp/tools/rule/save", mcpRuleSave)
	api.POST("/mcp/tools/rule/apply", mcpRuleApply)

	// Server-side AI analysis and configuration
	api.GET("/ai/config", getAIConfig)
	api.PUT("/ai/config", saveAIConfig)
	api.GET("/ai/models", listAIModels)
	api.POST("/ai/test", testAIConnection)
	api.POST("/ai/arsenal/analyze", analyzeArsenalWithAI)
	api.POST("/ai/arsenal/analyze/stream", analyzeArsenalStream)
	api.POST("/ai/chat", globalAIChat)
	api.POST("/ai/actions/confirm", confirmCopilotAction)
	api.GET("/ai/copilot/prompts", getCopilotPromptProfiles)
	api.GET("/ai/tool-invocations", listAIToolInvocations)

	// Arsenal 弹药库热发车网关与审核墙
	api.POST("/arsenals/ai/analyze", aiAnalyzeArsenal)
	api.POST("/arsenals/:type", debugPocGateway)
	api.GET("/arsenals/:type", getArsenals)
	api.GET("/arsenals/:type/:filename", getArsenal)
	api.POST("/arsenals/:type/:filename", saveArsenal)
	api.POST("/arsenals/:type/:filename/cancel", cancelDebugSessionGateway)
	api.POST("/arsenals/:type/:filename/approve", approveArsenal)
	api.DELETE("/arsenals/:type/:filename", deleteArsenal)

	// Dictionary Parsing Gateway (for workflow etc)
	api.GET("/dictionaries/workflow", getWorkflowDict)
	api.POST("/dictionaries/workflow", addWorkflowDict)
	api.PUT("/dictionaries/workflow/:product", updateWorkflowDict)
	api.DELETE("/dictionaries/workflow/:product", deleteWorkflowDict)

	api.GET("/dictionaries/fingerprint", getFingerprintDict)
	api.POST("/dictionaries/fingerprint", addFingerprintDict)
	api.PUT("/dictionaries/fingerprint/:product", updateFingerprintDict)
	api.DELETE("/dictionaries/fingerprint/:product", deleteFingerprintDict)

	api.GET("/dictionaries/dir", getDirDict)
	api.POST("/dictionaries/dir", addDirDict)
	api.PUT("/dictionaries/dir/:product", updateDirDict)
	api.DELETE("/dictionaries/dir/:product", deleteDirDict)

	// 规则清单（增量同步用）
	api.GET("/arsenals/manifest", getArsenalManifest)

	// Arsenal 安装/迁移 DB 导出（admin 用）
	api.GET("/arsenals/seed-db", exportArsenalSeedDB)

	// Arsenal DB 整体同步（Agent 用）
	api.GET("/arsenals/db", getArsenalDB)
	api.GET("/arsenals/db/hash", getArsenalDBHash)
	api.GET("/arsenals/db/stats", getArsenalDBStats)

	// API 密钥集中管理
	api.GET("/config/api-keys", getApiKeysConfig)
	api.PUT("/config/api-keys", saveApiKeysConfig)
	api.GET("/agents/config/api-keys", getAgentAPIConfig)

	// 用户管理 CRUD
	api.GET("/users", listUsers)
	api.POST("/users", createUser)
	api.PUT("/users/:id", updateUser)
	api.DELETE("/users/:id", deleteUser)

	// 角色与权限矩阵
	api.GET("/roles", listRoles)
	api.POST("/roles", createRole)
	api.PUT("/roles/:name", updateRole)
	api.DELETE("/roles/:name", deleteRole)
	api.GET("/tenants/:id/quotas", getTenantQuota)
	api.PUT("/tenants/:id/quotas", updateTenantQuota)

	// ====== 云资源编排 ======
	cloudHandler := cloudRuntime()
	// 云账号凭证管理
	api.GET("/cloud/accounts", cloudHandler.listCloudAccounts)
	api.POST("/cloud/accounts", cloudHandler.createCloudAccount)
	api.PUT("/cloud/accounts/:id", cloudHandler.updateCloudAccount)
	api.DELETE("/cloud/accounts/:id", cloudHandler.deleteCloudAccount)
	api.POST("/cloud/accounts/:id/test", cloudHandler.testCloudAccount)
	api.GET("/cloud/accounts/:id/bindings", cloudHandler.getCloudAccountBindings)
	api.PUT("/cloud/accounts/:id/bindings", cloudHandler.updateCloudAccountBindings)
	api.POST("/cloud/accounts/:id/oss/upload", cloudHandler.uploadAgentToOSS)
	api.POST("/cloud/accounts/:id/oss/upload-local", cloudHandler.uploadLocalAgentToOSS)
	api.POST("/cloud/accounts/:id/oss/test", cloudHandler.testOSSConnection)
	api.GET("/cloud/accounts/:id/oss/files", cloudHandler.listOSSFiles)
	api.POST("/cloud/accounts/:id/oss/delete", cloudHandler.deleteOSSFile)
	api.GET("/cloud/accounts/:id/release-files", cloudHandler.listReleaseFiles)
	api.GET("/cloud/accounts/:id/regions", cloudHandler.listCloudRegions)
	api.GET("/cloud/accounts/:id/discover", cloudHandler.discoverCloudResources)
	api.POST("/cloud/accounts/:id/auto-configure", cloudHandler.autoConfigureCloudAccount)
	api.POST("/cloud/accounts/:id/one-click-setup", cloudHandler.oneClickSetup)
	api.GET("/cloud/accounts/:id/permissions", cloudHandler.checkCloudPermissions)
	api.GET("/cloud/accounts/:id/price", cloudHandler.queryCloudPrice)
	api.GET("/cloud/accounts/:id/instance-types", cloudHandler.listAvailableInstanceTypes)
	// 伸缩策略管理
	api.GET("/cloud/policies", cloudHandler.listCloudPolicies)
	api.POST("/cloud/policies", cloudHandler.createCloudPolicy)
	api.PUT("/cloud/policies/:id", cloudHandler.updateCloudPolicy)
	api.DELETE("/cloud/policies/:id", cloudHandler.deleteCloudPolicy)
	api.POST("/cloud/policies/:id/toggle", cloudHandler.toggleCloudPolicy)
	// 云实例管理
	api.GET("/cloud/instances", cloudHandler.listCloudInstancesReal)
	api.POST("/cloud/instances", cloudHandler.createCloudInstanceManual)
	api.DELETE("/cloud/instances/:id", cloudHandler.deleteCloudInstanceReal)
	api.POST("/cloud/instances/:id/reboot", cloudHandler.rebootCloudInstance)
	api.POST("/cloud/instances/cleanup", cloudHandler.cleanupCloudInstances)
	// 云仪表盘
	api.GET("/cloud/dashboard", cloudHandler.cloudDashboard)

	// 客户端构建
	api.GET("/build/artifacts", listBuildArtifacts)
	api.GET("/build/jobs", listBuildJobs)
	api.GET("/build/jobs/:id", getBuildJob)
	api.GET("/build/jobs/:id/logs", getBuildJobLogs)
	api.POST("/build/jobs/:id/cancel", cancelBuildJob)
	api.POST("/build/jobs/:id/retry", retryBuildJob)
	api.POST("/build/client", triggerBuild)

	// MCP / API Key 管理
	api.GET("/mcp/keys", listMcpKeys)
	api.POST("/mcp/keys", saveMcpKey)
	api.DELETE("/mcp/keys/:id", deleteMcpKey)

	// 数据增强：趋势统计与报表
	api.GET("/stats/trends", getVulnTrends)
	api.GET("/stats/severity", getSeverityDistribution)
	api.GET("/stats/task-results", getTaskResultStats)
	api.GET("/stats/recent-high-vulns", getRecentHighVulns)

	// Agent 遥测日志
	api.GET("/agent-logs/summary", getAgentLogSummary)
	api.GET("/agent-logs/retention", getAgentLogRetention)
	api.PUT("/agent-logs/retention", updateAgentLogRetention)
	api.GET("/agent-logs/alerts", listAgentLogAlertEvents)
	api.GET("/agent-logs/alert-rules", listAgentLogAlertRules)
	api.POST("/agent-logs/alert-rules", createAgentLogAlertRule)
	api.DELETE("/agent-logs/alert-rules/:id", deleteAgentLogAlertRule)
	api.POST("/agent-logs/archive", archiveAgentLogs)
	api.GET("/agents/:id/logs", getAgentLogs)

	// 规则回滚
	api.POST("/arsenals/:type/:filename/rollback", rollbackArsenal)
}
