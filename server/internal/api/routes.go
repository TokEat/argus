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
	api.POST("/projects/:id/asset-discovery/fofa/query", queryProjectFOFAPreview)
	api.POST("/projects/:id/asset-discovery/hunter/query", queryProjectHunterPreview)
	api.POST("/projects/:id/asset-discovery/quake/query", queryProjectQuakePreview)
	api.GET("/projects/:id/asset-discovery/queries", listProjectDiscoveryQueries)
	api.GET("/projects/:id/asset-discovery/queries/:snapshot_id", getProjectDiscoveryQuery)
	api.GET("/projects/:id/asset-discovery/queries/:snapshot_id/export", exportProjectDiscoveryQuery)
	api.POST("/projects/:id/asset-discovery/queries/:snapshot_id/notebook-items", archiveProjectDiscoveryNotebookItems)
	api.GET("/projects/:id/asset-discovery/notebook-items", listProjectDiscoveryNotebookItemsOperations)
	api.PATCH("/projects/:id/asset-discovery/notebook-items/:item_id", patchProjectDiscoveryNotebookItem)
	api.POST("/projects/:id/asset-discovery/notebook-items/:item_id/remove", removeProjectDiscoveryNotebookItem)
	api.POST("/projects/:id/asset-discovery/notebook-items/:item_id/restore", restoreProjectDiscoveryNotebookItem)
	api.GET("/asset-discovery/notebook-items", listTenantDiscoveryNotebookItems)
	api.POST("/projects/:id/asset-discovery/notebook-distributions/preview", previewProjectNotebookDistribution)
	api.POST("/projects/:id/asset-discovery/notebook-distributions", materializeProjectNotebookDistribution)
	api.GET("/projects/:id/credential-dictionaries", listCredentialDictionaries)
	api.POST("/projects/:id/credential-dictionaries", createCredentialDictionary)
	api.POST("/projects/:id/credential-dictionaries/:dictionary_id/revisions", addCredentialDictionaryRevision)
	api.DELETE("/projects/:id/credential-dictionaries/:dictionary_id", deleteCredentialDictionary)
	api.GET("/projects/:id/subdomain-dictionaries", listSubdomainDictionaries)
	api.POST("/projects/:id/subdomain-dictionaries", createSubdomainDictionary)
	api.POST("/projects/:id/subdomain-dictionaries/:dictionary_id/revisions", addSubdomainDictionaryRevision)
	api.DELETE("/projects/:id/subdomain-dictionaries/:dictionary_id", deleteSubdomainDictionary)

	// 任务 CRUD
	api.GET("/tasks", getTasks)
	api.GET("/tasks/:id", getTaskDetail)
	api.GET("/tasks/:id/credential-findings", listTaskCredentialFindings)
	api.GET("/tasks/:id/config-revisions", getTaskConfigRevisions)
	api.GET("/tasks/:id/batches", listTaskBatches)
	api.POST("/tasks/:id/risk-validation/preview", previewTaskRiskValidation)
	api.POST("/tasks/:id/risk-validation", executeTaskRiskValidation)
	api.POST("/tasks/preview-selector", previewTaskSelector)
	api.POST("/tasks/plan-preview", previewTaskPlan)
	api.POST("/tasks/validate-targets", validateTargets)
	api.POST("/tasks", createTask)
	api.DELETE("/tasks/:id", deleteTask)
	api.POST("/tasks/:id/cancel", cancelTask)
	api.POST("/tasks/:id/stop", cancelTask)
	api.POST("/tasks/:id/pause", pauseTask)
	api.POST("/tasks/:id/resume", resumeTask)
	api.POST("/tasks/:id/retry", retryTask)
	api.POST("/tasks/:id/append", appendTargets) // 动态追加目标
	api.PUT("/tasks/:id/config", updateTaskConfig)
	api.POST("/tasks/:id/batches/:batch_id/pause", pauseTaskBatch)
	api.POST("/tasks/:id/batches/:batch_id/resume", resumeTaskBatch)
	api.POST("/tasks/:id/batches/:batch_id/stop", stopTaskBatch)
	api.POST("/tasks/:id/batches/:batch_id/retry", retryTaskBatch)
	api.DELETE("/tasks/:id/batches/:batch_id", archiveTaskBatch)

	// 队列监控
	api.GET("/queue/depth", getQueueDepth)

	// 漏洞资产与关联画像
	api.GET("/vulns", getVulns)
	api.GET("/assets", getAssets)
	api.GET("/fingerprints", getFingerprints)
	api.GET("/profiles", getProfiles)
	api.POST("/credential-findings/:id/reveal", revealCredentialFinding)
	api.GET("/poc-rules", listPocRules)
	api.GET("/active-fingerprint-rules", getActiveFingerprintRules)
	api.POST("/active-fingerprint-rules/inspect", inspectActiveFingerprint)
	// EXP 原生出口与审计。
	api.POST("/exp-egress-routes", createExpEgressRoute)
	api.DELETE("/exp-egress-routes/:route_id", revokeExpEgressRoute)
	api.GET("/exp-egress-audits", listExpEgressAudits)
	api.GET("/exp-egress-audits/:route_id", getExpEgressAudit)

	// Yaksha EXP 权威 Workspace。
	api.GET("/exps", listYakshaExps)
	api.POST("/exps", createYakshaExp)
	api.GET("/exps/:id", getYakshaExp)
	api.PATCH("/exps/:id", updateYakshaExp)
	api.DELETE("/exps/:id", deprecateYakshaExp)
	api.GET("/exps/:id/audits", listYakshaExpAudits)
	api.GET("/exps/:id/risk-waiver", getYakshaExpRiskWaiver)
	api.PUT("/exps/:id/risk-waiver", upsertYakshaExpRiskWaiver)
	api.DELETE("/exps/:id/risk-waiver", deleteYakshaExpRiskWaiver)
	api.POST("/exps/:id/draft/inspect", inspectYakshaExpDraft)
	api.POST("/exps/:id/draft/validate", validateYakshaExpDraft)
	api.POST("/exps/:id/draft/test", testYakshaExpDraft)
	api.GET("/exps/:id/revisions", listYakshaExpRevisions)
	api.POST("/exps/:id/revisions", createYakshaExpRevision)
	api.GET("/exps/:id/revisions/:revision", getYakshaExpRevision)
	api.GET("/exps/:id/revisions/:revision/sealed-package", getYakshaExpSealedPackage)
	api.POST("/exps/:id/revisions/:revision/inspect", inspectYakshaExpRevision)
	api.POST("/exps/:id/revisions/:revision/validate", validateYakshaExpRevision)
	api.POST("/exps/:id/revisions/:revision/publish", publishYakshaExpRevision)
	api.POST("/exps/:id/active-revision", setYakshaExpActiveRevision)
	api.GET("/exps/:id/revisions/:revision/test-cases", listYakshaExpTestCases)
	api.POST("/exps/:id/revisions/:revision/test-cases", createYakshaExpTestCase)
	api.PATCH("/exps/:id/test-cases/:case_id", updateYakshaExpTestCase)
	api.DELETE("/exps/:id/test-cases/:case_id", deleteYakshaExpTestCase)
	api.POST("/exps/:id/revisions/:revision/runs", runYakshaExpRevision)
	api.GET("/exp-runs", listYakshaExpRuns)
	api.GET("/exp-runs/:run_id", getYakshaExpRun)
	api.POST("/exp-runs/:run_id/cancel", cancelYakshaExpRun)
	api.GET("/exp-assets", listYakshaExpAssets)
	api.POST("/exp-assets", createYakshaExpAsset)
	api.GET("/exp-assets/:asset_id/versions/:version/content", getYakshaExpAssetContent)
	api.DELETE("/exp-assets/:asset_id/versions/:version", deleteYakshaExpAsset)

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

	// MCP support APIs for Codex/agent rule authoring loops.
	api.GET("/mcp/resources/argus-mcp/quickstart", mcpArgusMCPQuickstart)
	api.GET("/mcp/resources/argus-mcp/tool-guide", mcpArgusMCPToolGuide)
	api.GET("/mcp/resources/fingerprint/spec", mcpFingerprintSpec)
	api.GET("/mcp/resources/fingerprint/template", mcpFingerprintTemplate)
	api.GET("/mcp/resources/dir/spec", mcpDirSpec)
	api.GET("/mcp/resources/dir/template", mcpDirTemplate)
	api.GET("/mcp/resources/behavior-probe/spec", mcpBehaviorProbeSpec)
	api.GET("/mcp/resources/behavior-probe/template", mcpBehaviorProbeTemplate)
	api.GET("/mcp/resources/poc/spec", mcpPOCSpec)
	api.GET("/mcp/resources/poc/template", mcpPOCTemplate)
	api.GET("/mcp/resources/workflow/spec", mcpWorkflowSpec)
	api.GET("/mcp/resources/workflow/template", mcpWorkflowTemplate)
	api.GET("/mcp/resources/examples/fingerprint-poc-workflow", mcpFullChainExample)
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

	// Arsenal 弹药库热发车网关与审核墙
	api.POST("/arsenals/ai/analyze", aiAnalyzeArsenal)
	api.POST("/arsenals/:type", debugPocGateway)
	api.GET("/arsenals/:type", getArsenals)
	api.GET("/arsenals/:type/:filename", getArsenal)
	api.POST("/arsenals/:type/:filename", saveArsenal)
	api.POST("/arsenals/:type/:filename/cancel", cancelDebugSessionGateway)
	api.POST("/arsenals/:type/:filename/approve", approveArsenal)
	api.POST("/arsenals/:type/:filename/deprecate", deprecateArsenal)
	api.GET("/arsenals/:type/:filename/history", getArsenalHistory)
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
	api.GET("/cloud/accounts/:id/recommendations", cloudHandler.listCloudRecommendations)
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

	// MCP 管理
	api.GET("/mcp/admin/status", mcpAdminGetStatus)
	api.PUT("/mcp/admin/status", mcpAdminPutStatus)
	api.GET("/mcp/admin/clients", mcpAdminListClients)
	api.POST("/mcp/admin/clients/:id/revoke", mcpAdminRevokeClient)
	api.POST("/mcp/admin/clients/:id/disable", mcpAdminDisableClient)
	api.POST("/mcp/admin/clients/:id/enable", mcpAdminEnableClient)
	api.DELETE("/mcp/admin/clients/:id", mcpAdminDeleteClient)
	api.GET("/mcp/admin/sessions", mcpAdminListSessions)
	api.POST("/mcp/admin/sessions/revoke", mcpAdminRevokeSessions)
	api.GET("/mcp/admin/invocations", mcpAdminListInvocations)
	api.GET("/mcp/admin/events", mcpAdminListEvents)
	api.GET("/mcp/admin/tools", mcpAdminListTools)

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
