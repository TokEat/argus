package api

import (
	_ "embed"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

//go:embed prompts/copilot_profiles.yaml
var copilotPromptRegistryYAML []byte

type copilotPromptRegistry struct {
	Version   int                          `json:"version" yaml:"version"`
	Base      string                       `json:"base_prompt" yaml:"base_prompt"`
	Default   copilotPromptSpec            `json:"default" yaml:"default"`
	Profiles  map[string]copilotPromptSpec `json:"profiles" yaml:"profiles"`
	aliasByID map[string]string
}

type copilotPromptSpec struct {
	Label       string   `json:"label" yaml:"label"`
	Description string   `json:"description" yaml:"description"`
	Aliases     []string `json:"aliases,omitempty" yaml:"aliases"`
	MaxTurns    int      `json:"max_turns" yaml:"max_turns"`
	Tools       []string `json:"tools" yaml:"tools"`
	Prompt      string   `json:"prompt,omitempty" yaml:"prompt"`
}

type copilotPromptProfileView struct {
	Module       string   `json:"module"`
	Label        string   `json:"label"`
	Description  string   `json:"description"`
	Aliases      []string `json:"aliases,omitempty"`
	MaxTurns     int      `json:"max_turns"`
	Tools        []string `json:"tools"`
	Prompt       string   `json:"prompt"`
	SystemPrompt string   `json:"system_prompt"`
}

type copilotPromptRegistryResponse struct {
	Version   int                        `json:"version"`
	Base      string                     `json:"base_prompt"`
	Default   copilotPromptProfileView   `json:"default"`
	Profiles  []copilotPromptProfileView `json:"profiles"`
	Source    string                     `json:"source"`
	Reference string                     `json:"reference"`
}

var (
	copilotRegistryOnce sync.Once
	copilotRegistry     copilotPromptRegistry
	copilotRegistryErr  error
)

func loadCopilotPromptRegistry() (copilotPromptRegistry, error) {
	copilotRegistryOnce.Do(func() {
		var registry copilotPromptRegistry
		if err := yaml.Unmarshal(copilotPromptRegistryYAML, &registry); err != nil {
			copilotRegistryErr = err
			return
		}
		registry.Base = strings.TrimSpace(registry.Base)
		if registry.Version == 0 {
			registry.Version = 1
		}
		if registry.Default.MaxTurns <= 0 {
			registry.Default.MaxTurns = 4
		}
		if registry.Profiles == nil {
			registry.Profiles = map[string]copilotPromptSpec{}
		}
		registry.aliasByID = make(map[string]string)
		for module, spec := range registry.Profiles {
			for _, alias := range spec.Aliases {
				alias = strings.TrimSpace(alias)
				if alias != "" {
					registry.aliasByID[alias] = module
				}
			}
		}
		copilotRegistry = registry
	})
	return copilotRegistry, copilotRegistryErr
}

func resolveCopilotProfile(module string) copilotProfile {
	registry, err := loadCopilotPromptRegistry()
	if err != nil {
		log.Printf("failed to load copilot prompt registry: %v", err)
		return fallbackCopilotProfile()
	}
	spec := registry.resolveSpec(module)
	return copilotProfile{
		SystemPrompt: registry.renderSystemPrompt(spec),
		MaxTurns:     spec.MaxTurns,
		Tools:        append([]string(nil), spec.Tools...),
	}
}

func fallbackCopilotProfile() copilotProfile {
	return copilotProfile{
		SystemPrompt: "",
		MaxTurns:     4,
		Tools:        []string{"node_capacity"},
	}
}

func (r copilotPromptRegistry) resolveSpec(module string) copilotPromptSpec {
	module = strings.TrimSpace(module)
	spec := r.Default
	if spec.MaxTurns <= 0 {
		spec.MaxTurns = 4
	}
	spec.Tools = append([]string(nil), spec.Tools...)

	if module == "" || module == "global" {
		return spec
	}

	key := module
	if canonical, ok := r.aliasByID[module]; ok {
		key = canonical
	}
	moduleSpec, ok := r.Profiles[key]
	if !ok {
		return spec
	}

	spec.Label = moduleSpec.Label
	spec.Description = moduleSpec.Description
	spec.Aliases = append([]string(nil), moduleSpec.Aliases...)
	if moduleSpec.MaxTurns > 0 {
		spec.MaxTurns = moduleSpec.MaxTurns
	}
	if moduleSpec.Tools != nil {
		spec.Tools = append([]string(nil), moduleSpec.Tools...)
	}
	spec.Prompt = strings.TrimSpace(moduleSpec.Prompt)
	return spec
}

func (r copilotPromptRegistry) renderSystemPrompt(spec copilotPromptSpec) string {
	parts := []string{strings.TrimSpace(r.Base)}
	if strings.TrimSpace(spec.Prompt) != "" {
		parts = append(parts, strings.TrimSpace(spec.Prompt))
	}
	if len(spec.Tools) == 0 {
		parts = append(parts, "当前模块没有启用工具，请仅基于上下文和通用安全知识回答。")
	}
	return strings.Join(parts, "\n\n")
}

func getCopilotPromptProfiles(c *gin.Context) {
	registry, err := loadCopilotPromptRegistry()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, registry.toResponse())
}

func (r copilotPromptRegistry) toResponse() copilotPromptRegistryResponse {
	modules := make([]string, 0, len(r.Profiles))
	for module := range r.Profiles {
		modules = append(modules, module)
	}
	sort.Strings(modules)

	profiles := make([]copilotPromptProfileView, 0, len(modules))
	for _, module := range modules {
		spec := r.resolveSpec(module)
		profiles = append(profiles, copilotPromptProfileView{
			Module:       module,
			Label:        spec.Label,
			Description:  spec.Description,
			Aliases:      append([]string(nil), spec.Aliases...),
			MaxTurns:     spec.MaxTurns,
			Tools:        append([]string(nil), spec.Tools...),
			Prompt:       strings.TrimSpace(spec.Prompt),
			SystemPrompt: r.renderSystemPrompt(spec),
		})
	}

	defaultSpec := r.resolveSpec("global")
	return copilotPromptRegistryResponse{
		Version: r.Version,
		Base:    r.Base,
		Default: copilotPromptProfileView{
			Module:       "global",
			Label:        defaultSpec.Label,
			Description:  defaultSpec.Description,
			MaxTurns:     defaultSpec.MaxTurns,
			Tools:        append([]string(nil), defaultSpec.Tools...),
			Prompt:       strings.TrimSpace(defaultSpec.Prompt),
			SystemPrompt: r.renderSystemPrompt(defaultSpec),
		},
		Profiles:  profiles,
		Source:    "server/internal/api/prompts/copilot_profiles.yaml",
		Reference: "_ref_claude_code/claude-code-main/src/constants/prompts.ts",
	}
}
