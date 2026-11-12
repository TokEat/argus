package agent

import (
	"crypto/sha256"
	"fmt"
	"github.com/TokEat/argus/scanner/internal/arsenal"
	"path/filepath"
	"strings"
	"sync"
)

func (w *Worker) currentRuleVersion() string {
	w.rulesMu.Lock()
	defer w.rulesMu.Unlock()
	return w.ruleVersion
}

func (w *Worker) bindActivePackageSHA256Locked(manifest arsenal.RulePackageManifest) error {
	packageSHA256 := strings.TrimSpace(manifest.PackageSHA256)
	if len(packageSHA256) != sha256.Size*2 || packageSHA256 != strings.ToLower(packageSHA256) {
		return fmt.Errorf("materialized rule manifest package SHA-256 is invalid")
	}
	if w.activePackageSHA256 != "" {
		if w.activePackageSHA256 != packageSHA256 {
			return fmt.Errorf("active rule package SHA-256 changed without activation")
		}
		return nil
	}
	actual, err := arsenal.HashRulePackageFile(filepath.Join("data", "arsenal.db"))
	if err != nil {
		return err
	}
	if actual != packageSHA256 {
		return fmt.Errorf("materialized rule package SHA-256 mismatch")
	}
	w.activePackageSHA256 = actual
	return nil
}

// acquireTaskRuleUse confirms the active on-disk package identity and reserves
// it until the caller either publishes the task in runningTasks or fails.
func (w *Worker) acquireTaskRuleUse() (string, string, func(), error) {
	w.rulesMu.Lock()
	w.activatePendingRulesLocked()

	localHash := strings.TrimSpace(w.loadLocalDBHash())
	expectedVersion := strings.TrimSpace(w.ruleVersion)
	manifest, manifestErr := arsenal.ReadRulePackageManifest("config")
	if expectedVersion == "" && manifestErr == nil {
		// A pre-existing materialized package is authoritative during startup;
		// subsequent tasks still require the Worker version to agree with it.
		expectedVersion = strings.TrimSpace(manifest.RuleVersion)
		w.ruleVersion = expectedVersion
	}
	if manifestErr != nil || !arsenal.HasUsableRuleFiles("config") ||
		manifest.Hash != localHash || strings.TrimSpace(manifest.RuleVersion) != expectedVersion ||
		localHash == "" || expectedVersion == "" || manifest.PackageSHA256 == "" {
		if localHash == "" || expectedVersion == "" {
			w.rulesMu.Unlock()
			return "", "", nil, fmt.Errorf("agent rule package identity is unavailable (hash=%q version=%q)", localHash, expectedVersion)
		}
		if err := w.prepareOrActivateRulesLocked(localHash, expectedVersion); err != nil {
			w.rulesMu.Unlock()
			return "", "", nil, fmt.Errorf("materialize local arsenal.db: %w", err)
		}
		manifest, manifestErr = arsenal.ReadRulePackageManifest("config")
	}
	if manifestErr != nil || !arsenal.HasUsableRuleFiles("config") ||
		manifest.Hash != localHash || strings.TrimSpace(manifest.RuleVersion) != expectedVersion ||
		w.bindActivePackageSHA256Locked(manifest) != nil {
		w.rulesMu.Unlock()
		if manifestErr != nil {
			return "", "", nil, fmt.Errorf("read materialized rule manifest: %w", manifestErr)
		}
		return "", "", nil, fmt.Errorf("materialized rule manifest does not match current identity (want hash=%q version=%q, got hash=%q version=%q)", localHash, expectedVersion, manifest.Hash, manifest.RuleVersion)
	}

	w.mu.Lock()
	w.initializingRules++
	w.mu.Unlock()
	w.rulesMu.Unlock()

	var once sync.Once
	release := func() {
		once.Do(func() {
			w.mu.Lock()
			w.initializingRules--
			w.mu.Unlock()
			w.activatePendingRulesIfIdle()
		})
	}
	return manifest.PackageSHA256, manifest.RuleVersion, release, nil
}
