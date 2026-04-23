package db

import (
	"reflect"
	"testing"
)

func TestExtractFingerprintProductNamesFromFingerArray(t *testing.T) {
	payload := map[string]interface{}{
		"finger": []interface{}{"Apache", "PHP"},
	}

	got := extractFingerprintProductNames("Finger", "", payload)
	want := []string{"Apache", "PHP"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected products: want=%v got=%v", want, got)
	}
}

func TestExtractFingerprintProductNamesDedupesAndSplits(t *testing.T) {
	payload := map[string]interface{}{
		"finger": []interface{}{" Apache , PHP ", "PHP"},
	}

	got := extractFingerprintProductNames("Finger", "", payload)
	want := []string{"Apache", "PHP"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected products: want=%v got=%v", want, got)
	}
}

func TestExtractFingerprintProductNamesMergesPluginAndFinger(t *testing.T) {
	payload := map[string]interface{}{
		"finger": []interface{}{"Nginx", "Lua"},
	}

	got := extractFingerprintProductNames("Finger", "Nginx", payload)
	want := []string{"Nginx", "Lua"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected products: want=%v got=%v", want, got)
	}
}

func TestExtractFingerprintProductNamesNoSignalForGenericType(t *testing.T) {
	got := extractFingerprintProductNames("Finger", "", map[string]interface{}{})
	if len(got) != 0 {
		t.Fatalf("expected no products, got %v", got)
	}
}
