package aliyun

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
)

// ============================================================================
// 阿里云 AK/SK 权限检查模块
//
// 通过 STS GetCallerIdentity 获取身份信息，
// 通过 RAM ListPoliciesForUser/Group/Role 获取绑定的权限策略列表，
// 与 Argus 一键配置所需权限做自动比对。
// ============================================================================

// PermissionCheckResult 权限检查的完整返回结构
type PermissionCheckResult struct {
	// 身份信息
	AccountID    string `json:"account_id"`
	IdentityArn  string `json:"identity_arn"`
	IdentityType string `json:"identity_type"` // "Root" | "RAMUser" | "RAMRole" | "STSToken"
	UserName     string `json:"user_name,omitempty"`

	// 绑定的策略列表
	Policies []PolicyInfo `json:"policies"`

	// 一键配置权限比对
	RequiredPermissions []RequiredPermission `json:"required_permissions"`
	CanOneClickSetup    bool                 `json:"can_one_click_setup"`
	MissingPermissions  []string             `json:"missing_permissions"`
}

// PolicyInfo 单条策略信息
type PolicyInfo struct {
	PolicyName     string `json:"policy_name"`
	PolicyType     string `json:"policy_type"` // "System" | "Custom"
	Description    string `json:"description"`
	AttachSource   string `json:"attach_source"` // "User" | "Group:<组名>" | "Role"
	DefaultVersion string `json:"default_version,omitempty"`
	PolicyDocument string `json:"policy_document,omitempty"` // 自定义策略展示完整 JSON
}

// RequiredPermission 一键配置所需的单条权限
type RequiredPermission struct {
	ActionPattern string `json:"action_pattern"` // 例: "ecs:RunInstances"
	Description   string `json:"description"`
	Category      string `json:"category"` // "ECS" | "VPC" | "OSS"
	Satisfied     bool   `json:"satisfied"`
}

// argusRequiredActions 返回 Argus 一键配置所需的完整权限列表
func argusRequiredActions() []RequiredPermission {
	return []RequiredPermission{
		// ECS 实例管理
		{ActionPattern: "ecs:RunInstances", Description: "创建 ECS 实例", Category: "ECS"},
		{ActionPattern: "ecs:DescribeInstances", Description: "查询实例状态和 IP", Category: "ECS"},
		{ActionPattern: "ecs:DeleteInstances", Description: "批量销毁实例", Category: "ECS"},
		{ActionPattern: "ecs:RebootInstance", Description: "重启实例", Category: "ECS"},
		// ECS 资源发现
		{ActionPattern: "ecs:DescribeImages", Description: "查询可用系统镜像", Category: "ECS"},
		{ActionPattern: "ecs:DescribeInstanceTypes", Description: "查询可用实例规格", Category: "ECS"},
		{ActionPattern: "ecs:DescribeSecurityGroups", Description: "查询安全组", Category: "ECS"},
		{ActionPattern: "ecs:CreateSecurityGroup", Description: "自动创建安全组", Category: "ECS"},
		// VPC 网络
		{ActionPattern: "ecs:DescribeVpcs", Description: "查询 VPC 列表", Category: "VPC"},
		{ActionPattern: "ecs:CreateVpc", Description: "自动创建 VPC", Category: "VPC"},
		{ActionPattern: "ecs:DescribeVSwitches", Description: "查询交换机列表", Category: "VPC"},
		{ActionPattern: "ecs:CreateVSwitch", Description: "自动创建交换机", Category: "VPC"},
		{ActionPattern: "ecs:DescribeZones", Description: "查询可用区列表", Category: "VPC"},
		// OSS 存储
		{ActionPattern: "oss:CreateBucket", Description: "自动创建 OSS 存储桶", Category: "OSS"},
		{ActionPattern: "oss:PutBucketACL", Description: "设置存储桶 ACL 为私有", Category: "OSS"},
		{ActionPattern: "oss:PutObject", Description: "上传 Agent 二进制到 OSS", Category: "OSS"},
		{ActionPattern: "oss:GetObject", Description: "下载 Agent（预签名 URL）", Category: "OSS"},
		{ActionPattern: "oss:ListObjects", Description: "列出存储桶中文件", Category: "OSS"},
		{ActionPattern: "oss:DeleteObject", Description: "删除存储桶中文件", Category: "OSS"},
	}
}

// CheckPermissions 检查指定 AK/SK 的权限，返回完整的权限检查结果
func CheckPermissions(akID, akSecret, region string) (*PermissionCheckResult, error) {
	// STS/RAM 是全局服务，不依赖特定地域；未指定时默认用 cn-hangzhou
	if region == "" {
		region = "cn-hangzhou"
	}

	result := &PermissionCheckResult{
		Policies:            make([]PolicyInfo, 0),
		RequiredPermissions: argusRequiredActions(),
		MissingPermissions:  make([]string, 0),
	}


	// ========================
	// Step 1: 获取调用者身份
	// ========================
	stsClient, err := sts.NewClientWithAccessKey(region, akID, akSecret)
	if err != nil {
		return nil, fmt.Errorf("创建 STS 客户端失败: %w", err)
	}

	identityReq := sts.CreateGetCallerIdentityRequest()
	identityReq.Scheme = "https"
	identityRes, err := stsClient.GetCallerIdentity(identityReq)
	if err != nil {
		return nil, fmt.Errorf("获取调用者身份失败 (GetCallerIdentity): %w", err)
	}

	result.AccountID = identityRes.AccountId
	result.IdentityArn = identityRes.Arn
	result.IdentityType = parseIdentityType(identityRes.Arn)

	// ========================
	// Step 2: 根据身份类型查询权限策略
	// ========================
	if result.IdentityType == "Root" {
		// Root 账号拥有所有权限，直接标记
		result.Policies = append(result.Policies, PolicyInfo{
			PolicyName:   "AdministratorAccess",
			PolicyType:   "System",
			Description:  "主账号拥有所有权限（等价于 AdministratorAccess）",
			AttachSource: "RootAccount",
		})
	} else {
		// RAM 用户 / RAM 角色 / STS Token → 调用 RAM API 查询策略
		ramClient, err := ram.NewClientWithAccessKey(region, akID, akSecret)
		if err != nil {
			return nil, fmt.Errorf("创建 RAM 客户端失败: %w", err)
		}

		switch result.IdentityType {
		case "RAMUser":
			userName := extractUserName(identityRes.Arn)
			result.UserName = userName
			fetchUserPolicies(ramClient, userName, result)
			fetchUserGroupPolicies(ramClient, userName, result)

		case "RAMRole":
			roleName := extractRoleName(identityRes.Arn)
			result.UserName = roleName
			fetchRolePolicies(ramClient, roleName, result)

		case "STSToken":
			// STS Token 通常是通过 AssumeRole 获取的，尝试提取角色名
			roleName := extractRoleNameFromSTS(identityRes.Arn)
			if roleName != "" {
				result.UserName = roleName
				fetchRolePolicies(ramClient, roleName, result)
			}
		}

		// 尝试获取自定义策略的 Policy Document
		fetchPolicyDocuments(ramClient, result)
	}

	// ========================
	// Step 3: 权限比对
	// ========================
	evaluatePermissions(result)

	return result, nil
}

// parseIdentityType 从 ARN 解析身份类型
// 格式示例:
//
//	Root:     acs:ram::123456:root
//	RAMUser:  acs:ram::123456:user/username
//	RAMRole:  acs:sts::123456:assumed-role/rolename/session
//	STSToken: acs:sts::123456:assumed-role/rolename/sts-session
func parseIdentityType(arn string) string {
	if strings.Contains(arn, ":root") {
		return "Root"
	}
	if strings.Contains(arn, ":user/") {
		return "RAMUser"
	}
	if strings.Contains(arn, ":assumed-role/") {
		return "RAMRole"
	}
	if strings.Contains(arn, ":role/") {
		return "RAMRole"
	}
	return "STSToken"
}

// extractUserName 从 ARN 中提取 RAM 用户名
func extractUserName(arn string) string {
	idx := strings.Index(arn, ":user/")
	if idx == -1 {
		return ""
	}
	return arn[idx+6:]
}

// extractRoleName 从 ARN 中提取角色名
func extractRoleName(arn string) string {
	idx := strings.Index(arn, ":role/")
	if idx == -1 {
		return extractRoleNameFromSTS(arn)
	}
	return arn[idx+6:]
}

// extractRoleNameFromSTS 从 STS assumed-role ARN 中提取角色名
func extractRoleNameFromSTS(arn string) string {
	idx := strings.Index(arn, ":assumed-role/")
	if idx == -1 {
		return ""
	}
	rest := arn[idx+14:]
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// fetchUserPolicies 查询 RAM 用户直接绑定的策略
func fetchUserPolicies(client *ram.Client, userName string, result *PermissionCheckResult) {
	req := ram.CreateListPoliciesForUserRequest()
	req.Scheme = "https"
	req.UserName = userName

	res, err := client.ListPoliciesForUser(req)
	if err != nil {
		log.Printf("[Permission] ListPoliciesForUser(%s) error: %v", userName, err)
		return
	}

	for _, p := range res.Policies.Policy {
		result.Policies = append(result.Policies, PolicyInfo{
			PolicyName:     p.PolicyName,
			PolicyType:     p.PolicyType,
			Description:    p.Description,
			AttachSource:   "User",
			DefaultVersion: p.DefaultVersion,
		})
	}
}

// fetchUserGroupPolicies 查询 RAM 用户所在用户组的策略
func fetchUserGroupPolicies(client *ram.Client, userName string, result *PermissionCheckResult) {
	groupReq := ram.CreateListGroupsForUserRequest()
	groupReq.Scheme = "https"
	groupReq.UserName = userName

	groupRes, err := client.ListGroupsForUser(groupReq)
	if err != nil {
		log.Printf("[Permission] ListGroupsForUser(%s) error: %v", userName, err)
		return
	}

	for _, g := range groupRes.Groups.Group {
		policyReq := ram.CreateListPoliciesForGroupRequest()
		policyReq.Scheme = "https"
		policyReq.GroupName = g.GroupName

		policyRes, err := client.ListPoliciesForGroup(policyReq)
		if err != nil {
			log.Printf("[Permission] ListPoliciesForGroup(%s) error: %v", g.GroupName, err)
			continue
		}

		for _, p := range policyRes.Policies.Policy {
			result.Policies = append(result.Policies, PolicyInfo{
				PolicyName:     p.PolicyName,
				PolicyType:     p.PolicyType,
				Description:    p.Description,
				AttachSource:   fmt.Sprintf("Group:%s", g.GroupName),
				DefaultVersion: p.DefaultVersion,
			})
		}
	}
}

// fetchRolePolicies 查询 RAM 角色绑定的策略
func fetchRolePolicies(client *ram.Client, roleName string, result *PermissionCheckResult) {
	req := ram.CreateListPoliciesForRoleRequest()
	req.Scheme = "https"
	req.RoleName = roleName

	res, err := client.ListPoliciesForRole(req)
	if err != nil {
		log.Printf("[Permission] ListPoliciesForRole(%s) error: %v", roleName, err)
		return
	}

	for _, p := range res.Policies.Policy {
		result.Policies = append(result.Policies, PolicyInfo{
			PolicyName:     p.PolicyName,
			PolicyType:     p.PolicyType,
			Description:    p.Description,
			AttachSource:   "Role",
			DefaultVersion: p.DefaultVersion,
		})
	}
}

// fetchPolicyDocuments 获取自定义策略的 Policy Document
func fetchPolicyDocuments(client *ram.Client, result *PermissionCheckResult) {
	for i, p := range result.Policies {
		if p.PolicyType != "Custom" {
			continue
		}

		req := ram.CreateGetPolicyVersionRequest()
		req.Scheme = "https"
		req.PolicyName = p.PolicyName
		req.PolicyType = "Custom"
		req.VersionId = p.DefaultVersion

		res, err := client.GetPolicyVersion(req)
		if err != nil {
			log.Printf("[Permission] GetPolicyVersion(%s) error: %v", p.PolicyName, err)
			continue
		}

		result.Policies[i].PolicyDocument = res.PolicyVersion.PolicyDocument
	}
}

// evaluatePermissions 比对已有权限与所需权限
func evaluatePermissions(result *PermissionCheckResult) {
	// 收集所有策略 → 提取 Action 集合
	allActions := collectAllActions(result)

	// Root 账号 → 全部满足
	if result.IdentityType == "Root" {
		for i := range result.RequiredPermissions {
			result.RequiredPermissions[i].Satisfied = true
		}
		result.CanOneClickSetup = true
		return
	}

	// 逐条检查所需权限
	allSatisfied := true
	for i, req := range result.RequiredPermissions {
		satisfied := isActionSatisfied(req.ActionPattern, allActions)
		result.RequiredPermissions[i].Satisfied = satisfied
		if !satisfied {
			allSatisfied = false
			result.MissingPermissions = append(result.MissingPermissions, req.ActionPattern)
		}
	}
	result.CanOneClickSetup = allSatisfied
}

// actionSet 用于快速判断权限是否满足
type actionSet struct {
	exact     map[string]bool // 精确 Action，如 "ecs:RunInstances"
	wildcards []string        // 通配符 Action，如 "ecs:*", "*"
}

// collectAllActions 从所有策略中提取 Action 集合
func collectAllActions(result *PermissionCheckResult) *actionSet {
	as := &actionSet{
		exact:     make(map[string]bool),
		wildcards: make([]string, 0),
	}

	for _, p := range result.Policies {
		// 系统策略根据名称匹配已知的 FullAccess 策略
		if p.PolicyType == "System" {
			addSystemPolicyActions(p.PolicyName, as)
			continue
		}

		// 自定义策略 → 解析 Policy Document
		if p.PolicyDocument != "" {
			parseDocumentActions(p.PolicyDocument, as)
		}
	}

	return as
}

// wellKnownSystemPolicies 常见系统策略 → 对应的 Action 通配符
var wellKnownSystemPolicies = map[string][]string{
	"AdministratorAccess": {"*"},
	"AliyunECSFullAccess": {"ecs:*"},
	"AliyunECSReadOnlyAccess": {
		"ecs:Describe*",
	},
	"AliyunVPCFullAccess":       {"vpc:*", "ecs:DescribeVpcs", "ecs:CreateVpc", "ecs:DeleteVpc", "ecs:DescribeVSwitches", "ecs:CreateVSwitch", "ecs:DeleteVSwitch", "ecs:DescribeZones"},
	"AliyunVPCReadOnlyAccess":   {"vpc:Describe*"},
	"AliyunOSSFullAccess":       {"oss:*"},
	"AliyunOSSReadOnlyAccess":   {"oss:Get*", "oss:List*"},
	"AliyunRAMFullAccess":       {"ram:*"},
	"AliyunSTSAssumeRoleAccess": {"sts:AssumeRole"},
}

func addSystemPolicyActions(policyName string, as *actionSet) {
	actions, ok := wellKnownSystemPolicies[policyName]
	if !ok {
		// 未知系统策略，记录但不能推断权限
		return
	}

	for _, action := range actions {
		if strings.Contains(action, "*") {
			as.wildcards = append(as.wildcards, action)
		} else {
			as.exact[strings.ToLower(action)] = true
		}
	}
}

// policyDocument 用于解析 RAM Policy Document JSON
type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"` // string 或 []string
	Resource interface{} `json:"Resource"`
}

func parseDocumentActions(document string, as *actionSet) {
	var doc policyDocument
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		log.Printf("[Permission] Failed to parse policy document: %v", err)
		return
	}

	for _, stmt := range doc.Statement {
		if strings.ToLower(stmt.Effect) != "allow" {
			continue // 忽略 Deny 语句
		}

		actions := extractStringSlice(stmt.Action)
		for _, action := range actions {
			action = strings.TrimSpace(action)
			if action == "" {
				continue
			}
			if strings.Contains(action, "*") {
				as.wildcards = append(as.wildcards, action)
			} else {
				as.exact[strings.ToLower(action)] = true
			}
		}
	}
}

// extractStringSlice 将 string 或 []string 统一为 []string
func extractStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// isActionSatisfied 检查某个 Action 是否被满足
func isActionSatisfied(action string, as *actionSet) bool {
	actionLower := strings.ToLower(action)

	// 精确匹配
	if as.exact[actionLower] {
		return true
	}

	// 通配符匹配
	for _, pattern := range as.wildcards {
		if matchWildcard(pattern, action) {
			return true
		}
	}

	return false
}

// matchWildcard 支持简单的通配符匹配
// 例: "ecs:*" 匹配 "ecs:RunInstances"
//
//	"ecs:Describe*" 匹配 "ecs:DescribeInstances"
//	"*" 匹配任何 Action
func matchWildcard(pattern, action string) bool {
	patternLower := strings.ToLower(pattern)
	actionLower := strings.ToLower(action)

	if patternLower == "*" {
		return true
	}

	if !strings.Contains(patternLower, "*") {
		return patternLower == actionLower
	}

	// 简单前缀通配符: "ecs:*" → prefix="ecs:"
	if strings.HasSuffix(patternLower, "*") {
		prefix := strings.TrimSuffix(patternLower, "*")
		return strings.HasPrefix(actionLower, prefix)
	}

	// 其他复杂通配符 → 尝试简单 strings.Replace 处理
	// 将 * 替换为正则风格匹配（简化版）
	parts := strings.SplitN(patternLower, "*", 2)
	if len(parts) == 2 {
		return strings.HasPrefix(actionLower, parts[0]) && strings.HasSuffix(actionLower, parts[1])
	}

	return false
}
