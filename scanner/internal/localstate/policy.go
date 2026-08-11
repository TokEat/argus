package localstate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	LocalPolicySchemaVersion = "argus-local-policy/v1"
	LocalPolicyFileName      = "config.yaml"
	maxLocalPolicyBytes      = 64 << 10
)

type Duration time.Duration

func (duration Duration) Value() time.Duration {
	return time.Duration(duration)
}

func (duration Duration) MarshalYAML() (any, error) {
	return time.Duration(duration).String(), nil
}

func (duration *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node == nil || node.Kind != yaml.ScalarNode {
		return errors.New("duration must be a scalar string")
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(node.Value))
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", node.Value, err)
	}
	*duration = Duration(parsed)
	return nil
}

type LocalTTLPolicy struct {
	Liveness       Duration `yaml:"liveness"`
	Port           Duration `yaml:"port"`
	Protocol       Duration `yaml:"protocol"`
	Web            Duration `yaml:"web"`
	Fingerprint    Duration `yaml:"fingerprint"`
	RiskValidation Duration `yaml:"risk_validation"`
}

type LocalRevalidationPolicy struct {
	LivenessEveryRun      bool     `yaml:"liveness_every_run"`
	KnownServicesEveryRun bool     `yaml:"known_services_every_run"`
	Timeout               Duration `yaml:"timeout"`
	Concurrency           int      `yaml:"concurrency"`
	MaxEndpoints          int      `yaml:"max_endpoints"`
	LivenessPorts         []int    `yaml:"liveness_ports"`
}

type LocalPolicy struct {
	SchemaVersion string                  `yaml:"schema_version"`
	TTL           LocalTTLPolicy          `yaml:"ttl"`
	Revalidation  LocalRevalidationPolicy `yaml:"revalidation"`
}

func DefaultLocalPolicy() LocalPolicy {
	return LocalPolicy{
		SchemaVersion: LocalPolicySchemaVersion,
		TTL: LocalTTLPolicy{
			Liveness: Duration(5 * time.Minute), Port: Duration(time.Hour),
			Protocol: Duration(6 * time.Hour), Web: Duration(6 * time.Hour),
			Fingerprint: Duration(6 * time.Hour), RiskValidation: Duration(24 * time.Hour),
		},
		Revalidation: LocalRevalidationPolicy{
			LivenessEveryRun: true, KnownServicesEveryRun: true,
			Timeout: Duration(200 * time.Millisecond), Concurrency: 64, MaxEndpoints: 512,
			LivenessPorts: []int{80, 443, 3389, 445, 22},
		},
	}
}

// LoadLocalPolicy creates a documented default policy once, then strictly
// decodes the local file under a process-wide lock. Typos and unsafe values do
// not silently change scan coverage decisions.
func LoadLocalPolicy(home Home) (LocalPolicy, error) {
	layout, err := EnsureLayout(home)
	if err != nil {
		return LocalPolicy{}, err
	}
	lock, locked, err := acquireFileLock(filepath.Join(layout.Root, ".config.lock"), false)
	if err != nil {
		return LocalPolicy{}, err
	}
	if !locked {
		return LocalPolicy{}, errors.New("local policy lock was not acquired")
	}
	defer releaseFileLock(lock)

	path := filepath.Join(layout.Root, LocalPolicyFileName)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		encoded, marshalErr := yaml.Marshal(DefaultLocalPolicy())
		if marshalErr != nil {
			return LocalPolicy{}, fmt.Errorf("encode default local policy: %w", marshalErr)
		}
		if writeErr := writeFileAtomic(path, encoded, 0o600); writeErr != nil {
			return LocalPolicy{}, fmt.Errorf("create default local policy: %w", writeErr)
		}
	} else if err != nil {
		return LocalPolicy{}, fmt.Errorf("inspect local policy: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return LocalPolicy{}, fmt.Errorf("inspect local policy: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return LocalPolicy{}, errors.New("local policy must be a regular file")
	}
	if info.Size() > maxLocalPolicyBytes {
		return LocalPolicy{}, fmt.Errorf("local policy exceeds %d bytes", maxLocalPolicyBytes)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return LocalPolicy{}, fmt.Errorf("read local policy: %w", err)
	}
	if err := validateLocalPolicyShape(contents); err != nil {
		return LocalPolicy{}, err
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(contents)))
	decoder.KnownFields(true)
	var policy LocalPolicy
	if err := decoder.Decode(&policy); err != nil {
		return LocalPolicy{}, fmt.Errorf("decode local policy: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return LocalPolicy{}, errors.New("local policy must contain one YAML document")
		}
		return LocalPolicy{}, fmt.Errorf("decode trailing local policy document: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return LocalPolicy{}, err
	}
	return policy, nil
}

func validateLocalPolicyShape(contents []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return fmt.Errorf("decode local policy structure: %w", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("local policy must be a YAML mapping")
	}
	require := func(node *yaml.Node, path string, keys ...string) error {
		if node == nil || node.Kind != yaml.MappingNode {
			return fmt.Errorf("local policy %s must be a mapping", path)
		}
		present := make(map[string]*yaml.Node, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			present[node.Content[index].Value] = node.Content[index+1]
		}
		for _, key := range keys {
			if present[key] == nil {
				return fmt.Errorf("local policy %s.%s is required", path, key)
			}
		}
		return nil
	}
	root := document.Content[0]
	if err := require(root, "root", "schema_version", "ttl", "revalidation"); err != nil {
		return err
	}
	lookup := func(node *yaml.Node, key string) *yaml.Node {
		for index := 0; index+1 < len(node.Content); index += 2 {
			if node.Content[index].Value == key {
				return node.Content[index+1]
			}
		}
		return nil
	}
	if err := require(lookup(root, "ttl"), "ttl", "liveness", "port", "protocol", "web", "fingerprint", "risk_validation"); err != nil {
		return err
	}
	return require(lookup(root, "revalidation"), "revalidation",
		"liveness_every_run", "known_services_every_run", "timeout", "concurrency", "max_endpoints", "liveness_ports")
}

func (policy LocalPolicy) Validate() error {
	if policy.SchemaVersion != LocalPolicySchemaVersion {
		return fmt.Errorf("unsupported local policy schema %q", policy.SchemaVersion)
	}
	for name, value := range map[string]Duration{
		"ttl.liveness": policy.TTL.Liveness, "ttl.port": policy.TTL.Port,
		"ttl.protocol": policy.TTL.Protocol, "ttl.web": policy.TTL.Web,
		"ttl.fingerprint": policy.TTL.Fingerprint, "ttl.risk_validation": policy.TTL.RiskValidation,
	} {
		if value.Value() <= 0 || value.Value() > 30*24*time.Hour {
			return fmt.Errorf("local policy %s must be greater than zero and at most 720h", name)
		}
	}
	timeout := policy.Revalidation.Timeout.Value()
	if timeout < 10*time.Millisecond || timeout > 10*time.Second {
		return errors.New("local policy revalidation.timeout must be between 10ms and 10s")
	}
	if policy.Revalidation.Concurrency < 1 || policy.Revalidation.Concurrency > 1024 {
		return errors.New("local policy revalidation.concurrency must be between 1 and 1024")
	}
	if policy.Revalidation.MaxEndpoints < 1 || policy.Revalidation.MaxEndpoints > 4096 {
		return errors.New("local policy revalidation.max_endpoints must be between 1 and 4096")
	}
	if len(policy.Revalidation.LivenessPorts) == 0 || len(policy.Revalidation.LivenessPorts) > 32 {
		return errors.New("local policy revalidation.liveness_ports must contain 1 to 32 ports")
	}
	seen := make(map[int]struct{}, len(policy.Revalidation.LivenessPorts))
	for _, port := range policy.Revalidation.LivenessPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("local policy liveness port %d is outside 1..65535", port)
		}
		if _, duplicate := seen[port]; duplicate {
			return fmt.Errorf("local policy liveness port %d is duplicated", port)
		}
		seen[port] = struct{}{}
	}
	return nil
}
