package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/credentialbundle"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
	"github.com/gin-gonic/gin"
)

type taskCreateRequest struct {
	ProjectID          string             `json:"project_id"`
	Name               string             `json:"name"`
	Targets            json.RawMessage    `json:"targets"`
	Config             json.RawMessage    `json:"config"`
	Priority           *int               `json:"priority"`
	TimeoutSec         *int               `json:"timeout_sec"`
	AgentSelector      json.RawMessage    `json:"agent_selector"`
	AgentSelectorRules json.RawMessage    `json:"agent_selector_rules"`
	SkipUnsupported    bool               `json:"skip_unsupported"`
	Policy             *scanpolicy.Policy `json:"policy,omitempty"`
	PlanHash           string             `json:"plan_hash,omitempty"`
}

type scanPolicyPlanRequest struct {
	ProjectID       string            `json:"project_id"`
	Targets         json.RawMessage   `json:"targets"`
	Policy          scanpolicy.Policy `json:"policy"`
	Priority        *int              `json:"priority,omitempty"`
	TimeoutSec      *int              `json:"timeout_sec,omitempty"`
	SkipUnsupported bool              `json:"skip_unsupported,omitempty"`
}

type scanPolicyStagePreview struct {
	ID             string   `json:"id"`
	DependsOn      []string `json:"depends_on,omitempty"`
	Enabled        bool     `json:"enabled"`
	Targets        int      `json:"targets,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	MatchedAgents  int      `json:"matched_agents,omitempty"`
	AvailableSlots int      `json:"available_slots,omitempty"`
	AgentReasons   []string `json:"agent_reasons,omitempty"`
}

type scanPolicyPlan struct {
	Policy            scanpolicy.Policy          `json:"policy"`
	PolicyHash        string                     `json:"policy_hash"`
	PlanHash          string                     `json:"plan_hash"`
	RuleVersion       string                     `json:"rule_version"`
	PortCount         int                        `json:"port_count"`
	TargetSummary     taskTargetSummary          `json:"target_summary"`
	Stages            []scanPolicyStagePreview   `json:"stages"`
	MatchedAgents     int                        `json:"matched_agents"`
	AvailableSlots    int                        `json:"available_slots"`
	AgentReasons      []string                   `json:"agent_reasons,omitempty"`
	EstimatedRequests int64                      `json:"estimated_requests"`
	CustomPairs       int                        `json:"custom_credential_pairs"`
	CredentialLimit   int                        `json:"credential_pair_limit"`
	ValidationBudget  scanPolicyValidationBudget `json:"validation_budget"`
	SkippedTargets    []invalidTarget            `json:"skipped_targets,omitempty"`
	ScannerConfig     string                     `json:"-"`
	SelectorRules     string                     `json:"-"`
	TargetsNormalized []string                   `json:"-"`
}

type scanPolicyValidationBudget struct {
	TargetConcurrency      int    `json:"target_concurrency"`
	RateLimit              int    `json:"rate_limit"`
	CredentialMaxPerTarget int    `json:"credential_max_per_target"`
	RiskBudgetBasis        string `json:"risk_budget_basis"`
}

func normalizeTaskScheduling(priorityInput, timeoutInput *int) (int, int, error) {
	priority, timeoutSec := 1, 3600
	if priorityInput != nil {
		priority = *priorityInput
	}
	if timeoutInput != nil {
		timeoutSec = *timeoutInput
	}
	if priority < 0 || priority > 2 {
		return 0, 0, errors.New("priority must be 0 (urgent), 1 (normal), or 2 (low)")
	}
	if timeoutSec < 0 {
		return 0, 0, errors.New("timeout_sec must be greater than or equal to 0")
	}
	return priority, timeoutSec, nil
}

func loadTaskScanPolicyView(tenantID, taskID string) (interface{}, []db.ScanStageDerivation) {
	derivations := make([]db.ScanStageDerivation, 0)
	if !db.DB.Migrator().HasTable(&db.ScanPolicyIntent{}) {
		return nil, derivations
	}
	var intent db.ScanPolicyIntent
	if err := db.DB.Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).First(&intent).Error; err != nil {
		return nil, derivations
	}
	var policy interface{}
	if json.Unmarshal([]byte(intent.PolicyJSON), &policy) != nil {
		policy = nil
	}
	_ = db.DB.Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).
		Order("created_at asc").Find(&derivations).Error
	return gin.H{
		"schema_version": intent.SchemaVersion, "policy": policy,
		"policy_hash": intent.PolicyHash, "plan_hash": intent.PlanHash,
		"risk_status": intent.RiskStatus, "credential_status": intent.CredentialStatus,
		"authorized_at": intent.AuthorizedAt,
	}, derivations
}

func newScanPolicyIntent(plan scanPolicyPlan, tenantID, projectID, rootTaskID, operatorID string) (*db.ScanPolicyIntent, error) {
	policyJSON, err := json.Marshal(plan.Policy)
	if err != nil {
		return nil, err
	}
	riskStatus, credentialStatus := db.ScanStageIntentSkipped, db.ScanStageIntentSkipped
	if plan.Policy.Capabilities.RiskValidation {
		riskStatus = db.ScanStageIntentPending
	}
	if plan.Policy.Capabilities.CredentialValidation {
		credentialStatus = db.ScanStageIntentPending
	}
	now := time.Now().UTC()
	return &db.ScanPolicyIntent{
		TenantID: tenantID, ProjectID: projectID, RootTaskID: rootTaskID,
		SchemaVersion: plan.Policy.SchemaVersion, PolicyJSON: string(policyJSON),
		PolicyHash: plan.PolicyHash, PlanHash: plan.PlanHash,
		RiskStatus: riskStatus, CredentialStatus: credentialStatus,
		AuthorizationActorID: operatorID, AuthorizedAt: &now,
	}, nil
}

func decorateTaskCreateResponse(response gin.H, plan *scanPolicyPlan) {
	if plan == nil {
		return
	}
	response["policy_hash"] = plan.PolicyHash
	response["plan_hash"] = plan.PlanHash
	response["stages"] = plan.Stages
}

func previewTaskPlan(c *gin.Context) {
	var req scanPolicyPlanRequest
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, ok := requireProjectAccess(c, req.ProjectID); !ok {
		return
	}
	plan, err := compileTaskScanPolicy(c, req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

func compileTaskScanPolicy(c *gin.Context, req scanPolicyPlanRequest) (scanPolicyPlan, error) {
	normalized, err := scanpolicy.Normalize(req.Policy)
	if err != nil {
		return scanPolicyPlan{}, err
	}
	if normalized.Credentials.PairLimit != scanpolicy.DefaultCredentialPairLimit && !currentUserIsAdmin(c) {
		return scanPolicyPlan{}, errors.New("only tenant admin can adjust the credential pair limit")
	}
	ports, err := scanpolicy.PortsForProfile(normalized.PortProfile, normalized.CustomPorts)
	if err != nil {
		return scanPolicyPlan{}, err
	}
	var targets []string
	var summary taskTargetSummary
	var skipped []invalidTarget
	if req.SkipUnsupported {
		rawTargets, parseErr := parseTargets(req.Targets)
		if parseErr != nil {
			return scanPolicyPlan{}, parseErr
		}
		rawTargets = normalizeTargetsForMode(rawTargets, taskTargetModeDirect)
		targets, skipped, _ = classifyTargets(rawTargets, taskTargetModeDirect)
		if len(targets) > 0 {
			targets, summary, err = validateTargetsByMode(targets, taskTargetModeDirect)
		}
	} else {
		targets, summary, err = parseAndValidateTargetsForMode(req.Targets, taskTargetModeDirect)
	}
	if err != nil {
		return scanPolicyPlan{}, err
	}
	if len(targets) == 0 {
		return scanPolicyPlan{}, errors.New("targets is empty")
	}
	if err := verifyPolicyDictionaryRefs(currentTenantID(c), req.ProjectID, normalized); err != nil {
		return scanPolicyPlan{}, err
	}
	customPairs, err := estimatedCustomCredentialPairs(normalized, currentTenantID(c), req.ProjectID)
	if err != nil {
		return scanPolicyPlan{}, err
	}

	config := defaultTaskScanConfig()
	config.Ports = ports
	config.PortScanType = string(normalized.ScanMethod)
	config.Subdomain = normalized.Capabilities.SubdomainDiscovery
	config.NoSubFinder = !normalized.Capabilities.SubdomainDiscovery
	config.NoSubdomainBruteForce = !normalized.Capabilities.SubdomainBruteforce
	config.NoHostBind = !normalized.Capabilities.HostBinding
	config.NoDirSearch = !normalized.Capabilities.DirectoryProbe
	config.AllowCDNAssets = normalized.Capabilities.AllowCDNAssets
	config.AllowLocalAreaDomain = normalized.Capabilities.AllowPrivateResolvedDomains
	// Discovery never executes validation. Child batches are sealed later.
	config.NoPoc = true
	config.GolangPoc = false
	config.DisableGeneralPoc = true
	config.NoInteractsh = true
	config.Password = ""
	config.PasswordFile = ""
	applyPolicyIntensity(&config, normalized.Intensity)
	configJSON, err := json.Marshal(config)
	if err != nil {
		return scanPolicyPlan{}, err
	}

	selectorRules := db.AgentSelectorRules{Match: db.SelectorValues{}, NotMatch: db.SelectorValues{}}
	for key, values := range normalized.Selector.Match {
		selectorRules.Match[key] = append([]string(nil), values...)
	}
	for key, values := range normalized.Selector.NotMatch {
		selectorRules.NotMatch[key] = append([]string(nil), values...)
	}
	if normalized.ScanMethod == scanpolicy.ScanMethodSYN {
		selectorRules.Match["scan_syn"] = []string{"v1"}
	} else {
		selectorRules.Match["scan_tcp"] = []string{"v1"}
	}
	if len(selectorRules.NotMatch) == 0 {
		selectorRules.NotMatch = nil
	}

	matched, slots, reasons := previewPolicyAgents(currentTenantID(c), selectorRules)
	riskRules := cloneSelectorRules(selectorRules)
	riskRules.Match["risk_validation"] = []string{"v1"}
	riskMatched, riskSlots, riskReasons := previewPolicyAgents(currentTenantID(c), riskRules)
	credentialRules := cloneSelectorRules(selectorRules)
	credentialRules.Match["credential_validation"] = []string{"v1"}
	credentialRules.Match["transport_tls"] = []string{"verified"}
	credentialMatched, credentialSlots, credentialReasons := previewPolicyAgents(currentTenantID(c), credentialRules)
	policyHash, _ := scanpolicy.Hash(normalized)
	ruleVersion := currentRuleVersionValue()
	planHash, err := hashScanPolicyPlan(req.ProjectID, targets, policyHash, ruleVersion)
	if err != nil {
		return scanPolicyPlan{}, err
	}
	portCount := scanpolicy.PortCount(ports)
	estimated := int64(portCount) * int64(len(targets))
	validationConcurrency, validationRate := validationBudgetLimits(normalized.Intensity)
	stages := []scanPolicyStagePreview{
		{ID: "host_discovery", Enabled: true, Targets: len(targets)},
		{ID: "port_scan", DependsOn: []string{"host_discovery"}, Enabled: true, Targets: len(targets)},
		{ID: "protocol_identification", DependsOn: []string{"port_scan"}, Enabled: true},
		{ID: "http_probe", DependsOn: []string{"protocol_identification"}, Enabled: true},
		{ID: "fingerprint", DependsOn: []string{"http_probe", "protocol_identification"}, Enabled: true},
		{ID: "risk_validation", DependsOn: []string{"fingerprint"}, Enabled: normalized.Capabilities.RiskValidation, Reason: "only approved enabled Workflow matches are sealed", MatchedAgents: riskMatched, AvailableSlots: riskSlots, AgentReasons: riskReasons},
		{ID: "credential_validation", DependsOn: []string{"protocol_identification"}, Enabled: normalized.Capabilities.CredentialValidation, Reason: "built-in service dictionary is always retained", MatchedAgents: credentialMatched, AvailableSlots: credentialSlots, AgentReasons: credentialReasons},
	}
	return scanPolicyPlan{
		Policy: normalized, PolicyHash: policyHash, PlanHash: planHash, RuleVersion: ruleVersion,
		PortCount: portCount, TargetSummary: summary, Stages: stages,
		MatchedAgents: matched, AvailableSlots: slots, AgentReasons: reasons,
		EstimatedRequests: estimated, CustomPairs: customPairs,
		CredentialLimit:  normalized.Credentials.PairLimit,
		ValidationBudget: scanPolicyValidationBudget{TargetConcurrency: validationConcurrency, RateLimit: validationRate, CredentialMaxPerTarget: normalized.Credentials.PairLimit, RiskBudgetBasis: "sealed workflow estimate after discovery"},
		SkippedTargets:   skipped,
		ScannerConfig:    string(configJSON), SelectorRules: db.SelectorRulesToJSON(selectorRules),
		TargetsNormalized: targets,
	}, nil
}

func cloneSelectorRules(input db.AgentSelectorRules) db.AgentSelectorRules {
	clone := db.AgentSelectorRules{Match: db.SelectorValues{}, NotMatch: db.SelectorValues{}}
	for key, values := range input.Match {
		clone.Match[key] = append([]string(nil), values...)
	}
	for key, values := range input.NotMatch {
		clone.NotMatch[key] = append([]string(nil), values...)
	}
	if len(clone.NotMatch) == 0 {
		clone.NotMatch = nil
	}
	return clone
}

func applyPolicyIntensity(config *taskScanConfig, intensity scanpolicy.Intensity) {
	switch intensity {
	case scanpolicy.IntensityLow:
		config.TCPPortScanThreads, config.SYNPortScanThreads = 200, 2000
		config.GetBannerThreads, config.WebThreads, config.GoPocThreads = 100, 50, 2
	case scanpolicy.IntensityHigh:
		config.TCPPortScanThreads, config.SYNPortScanThreads = 1500, 15000
		config.GetBannerThreads, config.WebThreads, config.GoPocThreads = 750, 300, 5
	default:
		config.TCPPortScanThreads, config.SYNPortScanThreads = 800, 8000
		config.GetBannerThreads, config.WebThreads, config.GoPocThreads = 400, 150, 3
	}
}

func verifyPolicyDictionaryRefs(tenantID, projectID string, policy scanpolicy.Policy) error {
	refs := append(append([]scanpolicy.DictionaryRef(nil), policy.Credentials.UsernameBooks...), policy.Credentials.PasswordBooks...)
	for _, ref := range refs {
		var revision db.CredentialDictionaryRevision
		err := db.DB.Table("credential_dictionary_revisions AS r").
			Select("r.*").
			Joins("JOIN credential_dictionaries d ON d.id = r.dictionary_id AND d.tenant_id = r.tenant_id AND d.project_id = r.project_id").
			Where("r.tenant_id = ? AND r.project_id = ? AND r.dictionary_id = ? AND r.revision = ? AND d.deleted_at IS NULL", tenantID, projectID, ref.ID, ref.Revision).
			First(&revision).Error
		if err != nil {
			return fmt.Errorf("dictionary %q revision %d is unavailable", ref.ID, ref.Revision)
		}
		if !strings.EqualFold(revision.SHA256, ref.SHA256) || revision.ItemCount != ref.Count {
			return fmt.Errorf("dictionary %q revision %d metadata changed", ref.ID, ref.Revision)
		}
	}
	return nil
}

func estimatedCustomCredentialPairs(policy scanpolicy.Policy, tenantID, projectID string) (int, error) {
	pairs, err := credentialbundle.LoadCustomPairs(db.DB, policy, tenantID, projectID, policy.Credentials.PairLimit)
	return len(pairs), err
}

func checkedCredentialPairCount(usernames, passwords, limit int) (int, error) {
	return credentialbundle.CheckedPairCount(usernames, passwords, limit)
}

func previewPolicyAgents(tenantID string, rules db.AgentSelectorRules) (int, int, []string) {
	var nodes []db.Node
	scopedNodeQuery(tenantID).Find(&nodes)
	matched, slots := 0, 0
	reasonSet := map[string]struct{}{}
	for _, node := range nodes {
		if !strings.EqualFold(node.Status, "alive") {
			continue
		}
		ok, reason := db.NodeMatchesSelectorRules(nil, rules, node.Tags)
		if !ok {
			if reason != "" {
				reasonSet[reason] = struct{}{}
			}
			continue
		}
		matched++
		if available := node.Capacity - node.RunningTasks; available > 0 {
			slots += available
		}
	}
	if matched == 0 {
		reasonSet["没有在线 Agent 满足扫描方式和标签条件"] = struct{}{}
	}
	reasons := make([]string, 0, len(reasonSet))
	for reason := range reasonSet {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	return matched, slots, reasons
}

func hashScanPolicyPlan(projectID string, targets []string, policyHash, ruleVersion string) (string, error) {
	canonicalTargets := append([]string(nil), targets...)
	sort.Strings(canonicalTargets)
	encoded, err := json.Marshal(struct {
		ProjectID   string   `json:"project_id"`
		Targets     []string `json:"targets"`
		PolicyHash  string   `json:"policy_hash"`
		RuleVersion string   `json:"rule_version"`
	}{projectID, canonicalTargets, policyHash, ruleVersion})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
