package gopocs

import "testing"

func TestPrintRowReturnsScalarValuesInsteadOfWritingStdout(t *testing.T) {
	trueValue := interface{}(true)
	bytesValue := interface{}([]byte("row"))
	nilValue := interface{}(nil)

	_, result := PrintRow([]interface{}{&trueValue, &bytesValue, &nilValue})
	if result != "True\nrow\nNULL\n" {
		t.Fatalf("unexpected scalar result: %q", result)
	}
}
