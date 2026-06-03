package pyexp

import (
	"strings"
	"testing"
)

func TestValidateRejectsInvalidParamName(t *testing.T) {
	content := []byte(`ARGUS_EXP = {
    "id": "exp-param-name",
    "name": "Param name",
    "risk_level": "low",
    "policy": {"capabilities": ["result.write"]},
    "params": {"bad-name": {"type": "string", "required": True}},
    "requirements": [],
}

def run(ctx):
    return ctx.result.success("ok")
`)
	err := Validate(content, true)
	if err == nil || !strings.Contains(err.Error(), "name must match") {
		t.Fatalf("Validate error = %v, want param name error", err)
	}
}

func TestValidateAllowsMainOnlyNativePythonAndEmptyCapabilities(t *testing.T) {
	content := []byte(`ARGUS_EXP = {
    "id": "exp-native-python",
    "name": "Native Python",
    "risk_level": "low",
    "policy": {"capabilities": []},
    "params": {},
    "requirements": [],
}

import ctypes
import os
import subprocess

def main():
    subprocess.run(["true"], check=False)
    os.system("true")
    ctypes.c_int(1)
    return 0
`)
	if err := Validate(content, true); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestParseTemplateIgnoresArgusExpInCommentAndDocstring(t *testing.T) {
	content := []byte(`# ARGUS_EXP = {"id": "fake-comment", "name": "Fake", "policy": {"capabilities": ["result.write"]}}
"""
ARGUS_EXP = {
    "id": "fake-docstring",
    "name": "Fake",
    "risk_level": "low",
    "policy": {"capabilities": ["result.write"]},
    "requirements": [],
}
"""

ARGUS_EXP = {
    "id": "real-exp",
    "name": "Real EXP",
    "risk_level": "low",
    "policy": {"capabilities": ["result.write"]},
    "params": {},
    "requirements": [],
}

def run(ctx):
    return ctx.result.success("ok")
`)
	tmpl, err := ParseTemplate(content)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if tmpl.ID != "real-exp" {
		t.Fatalf("template id = %q, want real-exp", tmpl.ID)
	}
}

func TestParamSchemaAndNormalizeRuntimeParams(t *testing.T) {
	content := []byte(`ARGUS_EXP = {
    "id": "exp-param-schema",
    "name": "Param schema",
    "risk_level": "low",
    "policy": {"capabilities": ["result.write"]},
    "params": {
        "marker": {"type": "string", "required": True, "default": "argus-proof", "pattern": "^[A-Za-z0-9_.-]{1,64}$"},
        "retries": {"type": "int", "default": 1, "min": 1, "max": 5},
        "mode": {"type": "string", "default": "verify", "enum": ["verify", "cleanup"]},
        "secret": {"type": "string", "sensitive": True},
    },
    "requirements": [],
}

def run(ctx):
    return ctx.result.success("ok")
`)
	tmpl, err := ParseTemplate(content)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if err := Validate(content, true); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	schema := ParamSchema(tmpl.Params)
	secret, _ := schema["secret"].(map[string]interface{})
	if secret["sensitive"] != true {
		t.Fatalf("secret sensitive flag = %#v", secret["sensitive"])
	}
	normalized, errs := NormalizeRuntimeParams(schema, map[string]interface{}{"retries": "3"})
	if len(errs) > 0 {
		t.Fatalf("NormalizeRuntimeParams errors = %v", errs)
	}
	if normalized["marker"] != "argus-proof" || normalized["mode"] != "verify" || normalized["retries"] != 3 {
		t.Fatalf("normalized params = %#v", normalized)
	}
}

func TestNormalizeRuntimeParamsRejectsUnknownPatternAndEnum(t *testing.T) {
	schema := map[string]interface{}{
		"marker": map[string]interface{}{"type": "string", "required": true, "pattern": "^[a-z]+$"},
		"mode":   map[string]interface{}{"type": "string", "enum": []interface{}{"safe", "deep"}},
	}
	_, errs := NormalizeRuntimeParams(schema, map[string]interface{}{
		"marker": "ABC",
		"mode":   "other",
		"extra":  "value",
	})
	if len(errs) != 3 {
		t.Fatalf("NormalizeRuntimeParams errors = %#v, want 3 errors", errs)
	}
}

func TestInferRuntimeParamsFromArgparseAddArgument(t *testing.T) {
	content := []byte(`ARGUS_EXP = {
    "id": "exp-argparse",
    "name": "Argparse EXP",
    "risk_level": "low",
    "policy": {"capabilities": ["result.write"]},
    "params": {},
    "requirements": [],
}

import argparse

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "Authine@123456"

def main():
    parser = argparse.ArgumentParser(description="token helper")
    parser.add_argument("-t", "--target", help="目标地址")
    parser.add_argument("-u", "--username", default=DEFAULT_USERNAME, help=f"用户名 (默认: {DEFAULT_USERNAME})")
    parser.add_argument("-p", "--password", default=DEFAULT_PASSWORD, help="密码")
    parser.add_argument("--grant-type", default="password", choices=["password", "client_credentials", "refresh_token"], help="OAuth2 grant_type")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP 超时秒数")
    parser.add_argument("--no-verify", action="store_true", help="跳过 SSL 证书验证")
    parser.add_argument("-k", action="store_true", dest="insecure", help="跳过 SSL 证书验证")
    args = parser.parse_args()
    if not args.target:
        parser.error("需要指定 -t/--target")
`)
	tmpl, err := ParseTemplate(content)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if err := Validate(content, true); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	target := tmpl.Params["target"]
	if target.Flag != "--target" || !target.Required || target.Description != "目标地址" {
		t.Fatalf("target param = %#v", target)
	}
	password := tmpl.Params["password"]
	if password.Default != nil || !password.Sensitive {
		t.Fatalf("password param = %#v", password)
	}
	schemaPassword := ParamSchema(tmpl.Params)["password"].(map[string]interface{})
	if _, ok := schemaPassword["default"]; ok {
		t.Fatalf("password schema leaked default = %#v", schemaPassword)
	}
	grantType := tmpl.Params["grant_type"]
	if grantType.Flag != "--grant-type" || len(grantType.Enum) != 3 || grantType.Default != "password" {
		t.Fatalf("grant_type param = %#v", grantType)
	}
	timeout := tmpl.Params["timeout"]
	if timeout.Type != "int" || timeout.Default != 15 {
		t.Fatalf("timeout param = %#v", timeout)
	}
	noVerify := tmpl.Params["no_verify"]
	if noVerify.Type != "bool" || noVerify.Default != false {
		t.Fatalf("no_verify param = %#v", noVerify)
	}
	insecure := tmpl.Params["insecure"]
	if insecure.Flag != "-k" || insecure.Type != "bool" {
		t.Fatalf("insecure param = %#v", insecure)
	}
}

func TestExplicitParamsMergeInferredArgparseMetadata(t *testing.T) {
	content := []byte(`ARGUS_EXP = {
    "id": "exp-explicit-merge",
    "name": "Explicit merge",
    "risk_level": "low",
    "policy": {"capabilities": ["result.write"]},
    "params": {
        "target": {"type": "string", "required": True, "description": "目标系统地址"}
    },
    "requirements": [],
}

import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="CLI target")
    parser.add_argument("--token", default="secret-token", help="token")
`)
	tmpl, err := ParseTemplate(content)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	target := tmpl.Params["target"]
	if target.Description != "目标系统地址" || target.Flag != "--target" || target.Source != "argparse" {
		t.Fatalf("target param = %#v", target)
	}
	token := tmpl.Params["token"]
	if !token.Sensitive || token.Default != nil {
		t.Fatalf("token param = %#v", token)
	}
}

func TestInferRuntimeParamsFromArgparsePositional(t *testing.T) {
	content := []byte(`ARGUS_EXP = {
    "id": "exp-argparse-positional",
    "name": "Argparse positional",
    "risk_level": "low",
    "policy": {"capabilities": ["result.write"]},
    "params": {},
    "requirements": [],
}

import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("payload", help="payload text")
`)
	tmpl, err := ParseTemplate(content)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	payload := tmpl.Params["payload"]
	if payload.Flag != "" || payload.Position != 1 || !payload.Required || payload.Placeholder != "payload" {
		t.Fatalf("payload param = %#v", payload)
	}
}

func TestInferRuntimeParamsFromUsageAndSysArgv(t *testing.T) {
	content := []byte(`ARGUS_EXP = {
    "id": "exp-sysargv",
    "name": "Sysargv EXP",
    "risk_level": "low",
    "policy": {"capabilities": ["result.write"]},
    "params": {},
    "requirements": [],
}

"""
用法:
  python3 obfuscate.py <base64字符串>
  python3 obfuscate.py --file Payload.class
"""

import sys

def main():
    if sys.argv[1] == "--file":
        return sys.argv[2]
    return sys.argv[1]
`)
	tmpl, err := ParseTemplate(content)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	fileParam := tmpl.Params["file"]
	if fileParam.Flag != "--file" || fileParam.Placeholder != "Payload.class" {
		t.Fatalf("file param = %#v", fileParam)
	}
	arg1 := tmpl.Params["arg1"]
	if arg1.Position != 1 || arg1.Type != "string" {
		t.Fatalf("arg1 param = %#v", arg1)
	}
}
