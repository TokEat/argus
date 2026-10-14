package crawler

import "testing"

func kindsOf(hits []SensitiveHit) map[string][]string {
	out := map[string][]string{}
	for _, h := range hits {
		out[h.Kind] = append(out[h.Kind], h.Value)
	}
	return out
}

func TestSensitiveScanSecrets(t *testing.T) {
	body := `
var cfg = {
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  gmap: "AIzaSyD4iE7xn0aaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  gh: "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJK",
  pat: "github_pat_11ABCDEFGHIJKLMNOP_abcdEFGHijklMNOPqrstUVWXyz0123456789abcdefghijKLMN",
  slack: "xoxb-123456789012-abcdefghijklmn",
  jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
  pem: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----",
  api_key: "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
  client_secret: "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o5p6",
  username: "zhang.wei",
  user: "li.na",
  password: "Str0ng!Pass",
};
`
	k := kindsOf(sensitiveScan(body))

	for _, want := range []string{"apikey", "token", "secret", "username", "account"} {
		if len(k[want]) == 0 {
			t.Errorf("expected kind %s in hits, got %+v", want, k)
		}
	}
	// AWS + Google + generic api_key → 3 个 apikey。
	if len(k["apikey"]) != 3 {
		t.Errorf("apikey count = %d, want 3 (%v)", len(k["apikey"]), k["apikey"])
	}
	// GitHub + github_pat + slack + JWT → 4 个 token。
	if len(k["token"]) != 4 {
		t.Errorf("token count = %d, want 4 (%v)", len(k["token"]), k["token"])
	}
	// PEM + client_secret → 2 个 secret。
	if len(k["secret"]) != 2 {
		t.Errorf("secret count = %d, want 2 (%v)", len(k["secret"]), k["secret"])
	}
	// 用户名赋值。
	for _, want := range []string{"zhang.wei", "li.na"} {
		found := false
		for _, v := range k["username"] {
			if v == want {
				found = true
			}
		}
		if !found {
			t.Errorf("username %s not found in %v", want, k["username"])
		}
	}
	// 值上限 200 字节。
	for kind, vals := range k {
		for _, v := range vals {
			if len(v) > 200 {
				t.Errorf("kind %s value exceeds 200 bytes", kind)
			}
		}
	}
}

func TestSensitiveScanNegative(t *testing.T) {
	body := `
apikey="YOUR_API_KEY"
token="abcdef"
password="123456"
user="a@b.com"
secret="xxxxxxxxxxxxxxxx"
username="12345678901"
`
	k := kindsOf(sensitiveScan(body))
	// 负例：占位符/单字符类/邮箱归 email/全数字 用户名 都不应命中对应类。
	if len(k["apikey"]) != 0 {
		t.Errorf("placeholder apikey should be filtered, got %v", k["apikey"])
	}
	if len(k["token"]) != 0 {
		t.Errorf("short single-class token should be filtered, got %v", k["token"])
	}
	if len(k["account"]) != 0 {
		t.Errorf("123456 password single-class should be filtered, got %v", k["account"])
	}
	if len(k["secret"]) != 0 {
		t.Errorf("all-same-char secret should be filtered, got %v", k["secret"])
	}
	// user="a@b.com" 不应产生 username（email 独占 @）。
	for _, v := range k["username"] {
		if v == "a@b.com" {
			t.Errorf("email-looking value leaked into username: %v", k["username"])
		}
	}
	// 但 a@b.com 应命中 email。
	if len(k["email"]) == 0 {
		t.Errorf("a@b.com should hit email, got %+v", k)
	}
}

func TestSensitiveScanSpanExclusion(t *testing.T) {
	// token= 后跟 JWT：provider 已定型 JWT，通用 tokenAssignRe 不应再发一条。
	body := `auth = { token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" }`
	k := kindsOf(sensitiveScan(body))
	if len(k["token"]) != 1 {
		t.Errorf("JWT after token= should emit exactly one token hit, got %v", k["token"])
	}
}
