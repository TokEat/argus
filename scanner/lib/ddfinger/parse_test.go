package ddfinger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
	"gopkg.in/yaml.v3"
)

func TestAllFingerprintRulesSingleCheckDoNotPanic(t *testing.T) {
	path := filepath.Join("..", "..", "common", "config", "finger.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var fingerprints map[string][]string
	if err := yaml.Unmarshal(data, &fingerprints); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	payloads := []struct {
		name   string
		header string
		body   string
		server string
		title  string
		icon   string
		status int
	}{
		{name: "empty"},
		{name: "typical-http", header: "Server: nginx\r\n", body: "<html>test</html>", server: "nginx", title: "Index", icon: "123", status: 200},
	}

	for product, rules := range fingerprints {
		for _, rule := range rules {
			parsed := ParseRule(rule)
			if leftover := unparsedFingerprintResidue(rule, parsed); strings.Contains(leftover, `:"`) {
				t.Errorf("product=%q rule=%q has unparsed Shodan/FOFA colon clause residue %q", product, rule, leftover)
			}
			finger := structs.FingerPEntity{ProductName: product, AllString: rule, Rule: parsed}
			for _, payload := range payloads {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("product=%q payload=%s rule=%q parsed=%d panic=%v", product, payload.name, rule, len(parsed), r)
						}
					}()
					_ = SingleCheck(finger, "http", payload.header, payload.body, payload.server, payload.title, "", 80, "/", "", payload.icon, payload.status, "text/html", "")
				}()
			}
		}
	}
}

func TestBoolEvalMalformedExpressionsDoNotPanic(t *testing.T) {
	cases := []string{
		`T|`,
		`|T`,
		`T|F|`,
		`(T`,
		`T)`,
		`T&`,
		`!`,
		``,
		`T || title:"netscaler gateway"`,
	}
	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("boolEval(%q) panicked: %v", expr, r)
				}
			}()
			if boolEval(expr) {
				t.Fatalf("boolEval(%q) matched a malformed expression", expr)
			}
		})
	}
}

func TestSingleCheckShodanColonOrDoesNotPanic(t *testing.T) {
	rule := `title="citrix gateway" || title:"netscaler gateway"`
	finger := structs.FingerPEntity{
		ProductName: "Citrix-Netscaler-Application-Delivery-Controller",
		AllString:   rule,
		Rule:        ParseRule(rule),
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SingleCheck panicked: %v", r)
		}
	}()
	matched := SingleCheck(finger, "https", "", "", "", "citrix gateway", "", 443, "/", "", "", 200, "text/html", "")
	if matched {
		t.Fatal("expected leftover Shodan colon clause not to evaluate as a successful OR")
	}
}

func TestCitrixNetscalerFingerprintUsesEqualsSyntax(t *testing.T) {
	rules := loadFingerprintRules(t, "Citrix-Netscaler-Application-Delivery-Controller")
	var matched bool
	for _, rule := range rules {
		if strings.Contains(rule, `title:"`) {
			t.Fatalf("fingerprint still uses Shodan colon syntax: %q", rule)
		}
		finger := structs.FingerPEntity{
			ProductName: "Citrix-Netscaler-Application-Delivery-Controller",
			AllString:   rule,
			Rule:        ParseRule(rule),
		}
		if SingleCheck(finger, "https", "", "", "", "NetScaler Gateway", "", 443, "/", "", "", 200, "text/html", "") {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("expected Citrix-Netscaler-Application-Delivery-Controller to match title NetScaler Gateway, rules=%v", rules)
	}
}

func TestBoolEvalBasicOperators(t *testing.T) {
	if !boolEval("T") || boolEval("F") {
		t.Fatal("expected T=true F=false")
	}
	if !boolEval("T|F") || !boolEval("F|T") || boolEval("F|F") {
		t.Fatal("OR truth table mismatch")
	}
	if !boolEval("T&T") || boolEval("T&F") || boolEval("F&T") {
		t.Fatal("AND truth table mismatch")
	}
	if !boolEval("!F") || boolEval("!T") {
		t.Fatal("NOT truth table mismatch")
	}
	if !boolEval("(T|F)&T") {
		t.Fatal("expected grouped expression to stay true")
	}
}

func TestDirProbeCheckRejectsPathOnlyAndReflectedErrors(t *testing.T) {
	pathOnly := structs.FingerPEntity{
		ProductName: "致远互联-OA",
		AllString:   `path="/seeyon/"`,
		Rule:        ParseRule(`path="/seeyon/"`),
	}
	if DirProbeCheck(pathOnly, "http", "", "403 Forbidden", "", "403 Forbidden", "", 8556, "/seeyon/", "", "", 403, "text/html", "") {
		t.Fatal("path-only rule must not identify a product on a directory probe")
	}
	if !SingleCheck(pathOnly, "http", "", "403 Forbidden", "", "403 Forbidden", "", 8556, "/seeyon/", "", "", 403, "text/html", "") {
		t.Fatal("passive SingleCheck should still honor explicit path rules")
	}

	reflected := structs.FingerPEntity{
		ProductName: "致远OA-M3-Server",
		AllString:   `body="/mobile_portal/"`,
		Rule:        ParseRule(`body="/mobile_portal/"`),
	}
	denied := `<html>403 Forbidden</html>URL: http://example.test/mobile_portal/`
	if DirProbeCheck(reflected, "http", "", denied, "", "403 Forbidden", "", 8556, "/mobile_portal/", "", "", 403, "text/html", "") {
		t.Fatal("generic 403 that only echoes the probe path must not match")
	}

	realPage := structs.FingerPEntity{
		ProductName: "致远互联-OA",
		AllString:   `path="/seeyon/" && body="seeyonProductId"`,
		Rule:        ParseRule(`path="/seeyon/" && body="seeyonProductId"`),
	}
	if !DirProbeCheck(realPage, "http", "", `var seeyonProductId = "A8"`, "", "致远A8", "", 80, "/seeyon/", "", "", 200, "text/html", "") {
		t.Fatal("expected distinctive 200 body to match during directory probe")
	}

	headerHit := structs.FingerPEntity{
		ProductName: "泛微-协同办公OA",
		AllString:   `header="ecology_JSessionid"`,
		Rule:        ParseRule(`header="ecology_JSessionid"`),
	}
	if !DirProbeCheck(headerHit, "http", "Set-Cookie: ecology_JSessionid=abc\r\n", "403 Forbidden", "", "403 Forbidden", "", 80, "/wui/index.html", "", "", 403, "text/html", "") {
		t.Fatal("distinctive product header should still match on 403")
	}
}

func unparsedFingerprintResidue(rule string, parsed []structs.RuleData) string {
	expr := rule
	for _, item := range parsed {
		if item.Start < 0 || item.End > len(expr) || item.Start > item.End {
			return expr
		}
		expr = expr[:item.Start] + "T" + expr[item.End:]
	}
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case 'T', 'F', '&', '|', '(', ')', '!', ' ':
			return -1
		default:
			return r
		}
	}, expr)
	return cleaned
}

func TestParseRuleMalformedExpressionsDoNotPanic(t *testing.T) {
	cases := []string{
		`="dangling-key"`,
		`=="dangling-key"`,
		`body="unterminated`,
		`body="`,
		`body="value" && = "bad"`,
	}
	for _, rule := range cases {
		t.Run(rule, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseRule panicked for %q: %v", rule, r)
				}
			}()
			_ = ParseRule(rule)
		})
	}
}

func TestParseRuleEmptyStringValue(t *testing.T) {
	rules := ParseRule(`path="/__bes/__ejb" && status="200" && body==""`)
	if len(rules) != 3 {
		t.Fatalf("expected 3 parsed rules, got %d", len(rules))
	}
	if rules[2].Key != "body" {
		t.Fatalf("expected body rule, got %q", rules[2].Key)
	}
	if rules[2].Value != "" {
		t.Fatalf("expected empty body value, got %q", rules[2].Value)
	}
	if rules[2].Op != 2 {
		t.Fatalf("expected equality op, got %d", rules[2].Op)
	}
}

func TestDataCheckIntTreatsDoubleEqualsAsEquality(t *testing.T) {
	if !dataCheckInt(2, 588710312, 588710312) {
		t.Fatal("expected op=2 to match equal integer values")
	}
	if dataCheckInt(2, 588710312, 1) {
		t.Fatal("expected op=2 to reject different integer values")
	}
}

func TestParaviewPASGRedirectFingerprintRuleMatches(t *testing.T) {
	rules := loadFingerprintRules(t, "派拉身份认证IAM")
	header := "HTTP/1.1 302 Found\r\nx-powered-by: PASG\r\nLocation: /selfcare/\r\n"
	body := `<p></p><p>PASG Redirecting to <a href="/selfcare/">/selfcare/</a></p>`

	for _, rule := range rules {
		finger := structs.FingerPEntity{
			ProductName: "派拉身份认证IAM",
			AllString:   rule,
			Rule:        ParseRule(rule),
		}
		if SingleCheck(finger, "https", header, body, "", "", "", 999, "/", "", "", 302, "text/html", "") {
			return
		}
	}

	t.Fatalf("expected 派拉身份认证IAM to match PASG 302 redirect, rules=%v", rules)
}

func TestKingdeeK3CloudDoesNotMatchReflectedProbePath(t *testing.T) {
	rules := loadFingerprintRules(t, "金蝶云星空")
	body := `<html><title>400 Bad Request</title>URL: http://example.test/k3cloud</html>`

	for _, rule := range rules {
		finger := structs.FingerPEntity{
			ProductName: "金蝶云星空",
			AllString:   rule,
			Rule:        ParseRule(rule),
		}
		if SingleCheck(finger, "http", "Server: nginx\r\n", body, "nginx", "400 Bad Request", "", 80, "/k3cloud", "", "", 400, "text/html", "") {
			t.Fatalf("reflected probe path matched 金蝶云星空 rule %q", rule)
		}
	}
}

func TestKingdeeK3CloudMatchesStrongLoginAsset(t *testing.T) {
	rules := loadFingerprintRules(t, "金蝶云星空")
	body := `<html><title>金蝶云星空</title><link href="./k3cloud/HTML5/content/themes/kd.ui.login.css"></html>`

	for _, rule := range rules {
		finger := structs.FingerPEntity{
			ProductName: "金蝶云星空",
			AllString:   rule,
			Rule:        ParseRule(rule),
		}
		if SingleCheck(finger, "http", "Server: Microsoft-IIS/10.0\r\n", body, "Microsoft-IIS/10.0", "金蝶云星空", "", 80, "/k3cloud", "", "", 200, "text/html", "") {
			return
		}
	}

	t.Fatalf("expected 金蝶云星空 strong login response to match, rules=%v", rules)
}

func TestKingdeeK3CloudMatchesIconHash(t *testing.T) {
	rules := loadFingerprintRules(t, "金蝶云星空")
	for _, rule := range rules {
		finger := structs.FingerPEntity{
			ProductName: "金蝶云星空",
			AllString:   rule,
			Rule:        ParseRule(rule),
		}
		if SingleCheck(finger, "http", "", "", "", "", "", 80, "/", "", "-1629133697", 200, "text/html", "") {
			return
		}
	}
	t.Fatalf("expected 金蝶云星空 icon hash to match, rules=%v", rules)
}

func TestKingdeeK3CloudKeepsActiveProbePath(t *testing.T) {
	path := filepath.Join("..", "..", "common", "config", "dir.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var probes map[string][]string
	if err := yaml.Unmarshal(data, &probes); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, probe := range probes["金蝶云星空"] {
		if probe == "/k3cloud" {
			return
		}
	}
	t.Fatalf("expected 金蝶云星空 active probe /k3cloud, got %v", probes["金蝶云星空"])
}

func TestDirYamlOmitsGenericProbePaths(t *testing.T) {
	probes := loadDirProbes(t)

	generic := map[string]struct{}{
		"/login": {}, "/login/": {}, "/admin/": {}, "/portal/": {},
		"/version": {}, "/ui/": {}, "/explore": {}, "/graph": {},
		"/ping": {}, "/docs/": {}, "/toLogin": {}, "/js/..;/actuator": {},
		"/login.jsp": {}, "/login.php": {}, "/login.do": {}, "/login.action": {},
	}
	for product, paths := range probes {
		for _, probe := range paths {
			if _, banned := generic[probe]; banned {
				t.Errorf("dir.yaml product %q uses generic probe %q; only keep paths that must be visited to identify the fingerprint", product, probe)
			}
		}
	}
}

func TestDirYamlOmitsPassiveIdentifiableOAProbes(t *testing.T) {
	probes := loadDirProbes(t)
	for _, product := range []string{
		"致远互联-OA",
		"致远OA-M3-Server",
		"泛微-协同办公OA",
		"泛微-EOffice",
		"ecology泛微e-office",
		"泛微-EMobile",
		"TDXK-通达OA",
		"用友-GRP-U8",
	} {
		if paths, ok := probes[product]; ok {
			t.Errorf("dir.yaml still probes %q at %v; homepage title/header/icon already identify it", product, paths)
		}
	}
}

func TestDirYamlKeepsMustVisitHiddenConsoles(t *testing.T) {
	probes := loadDirProbes(t)
	want := map[string]string{
		"Alibaba-Nacos": "/nacos/",
		"Alibaba-Druid": "/druid/index.html",
		"Apache-Tomcat": "/manager/html",
		"APACHE-Solr":   "/solr/",
		"金蝶云星空":         "/k3cloud",
		"百度-UEditor":    "/ueditor/ueditor.all.js",
		"畅捷通-TPlus":     "/tplus/",
	}
	for product, path := range want {
		found := false
		for _, probe := range probes[product] {
			if probe == path {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("dir.yaml missing must-visit probe %s %s, got %v", product, path, probes[product])
		}
	}
}

func loadDirProbes(t *testing.T) map[string][]string {
	t.Helper()
	path := filepath.Join("..", "..", "common", "config", "dir.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var probes map[string][]string
	if err := yaml.Unmarshal(data, &probes); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return probes
}

func loadFingerprintRules(t *testing.T, product string) []string {
	t.Helper()

	path := filepath.Join("..", "..", "common", "config", "finger.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var fingerprints map[string][]string
	if err := yaml.Unmarshal(data, &fingerprints); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	rules, ok := fingerprints[product]
	if !ok {
		t.Fatalf("product %q not found in %s", product, path)
	}
	if len(rules) == 0 {
		t.Fatalf("product %q has no rules in %s", product, path)
	}
	return rules
}
