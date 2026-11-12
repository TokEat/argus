package grpc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/TokEat/argus/shared/proto/go/scanplan"
)

func configWithResumePlan(raw string, plan *scanplan.ResumePlan, planHash string) ([]byte, error) {
	if plan == nil || len(plan.ReusedStages) == 0 {
		return nil, errors.New("resume config requires reusable stages")
	}
	configBytes := []byte(raw)
	if strings.TrimSpace(raw) == "" {
		configBytes = []byte("{}")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(configBytes, &fields); err != nil || fields == nil {
		return nil, errors.New("resume config must be a JSON object")
	}
	for _, field := range []string{"ResumePlan", "ResumePlanHash", "ObservationConfigHash"} {
		delete(fields, field)
	}
	encodedPlan, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	encodedPlanHash, _ := json.Marshal(planHash)
	rawConfigDigest := sha256.Sum256([]byte(raw))
	encodedConfigHash, _ := json.Marshal(hex.EncodeToString(rawConfigDigest[:]))
	fields["ResumePlan"] = encodedPlan
	fields["ResumePlanHash"] = encodedPlanHash
	fields["ObservationConfigHash"] = encodedConfigHash
	return json.Marshal(fields)
}
