package remote

import (
	"reflect"
	"strings"
	"testing"
)

func TestInstallStageWriterOnlyPublishesKnownCompleteLines(t *testing.T) {
	var stages []string
	writer := &installStageWriter{report: func(stage string) { stages = append(stages, stage) }}
	for _, chunk := range []string{
		"secret\nMXIOC_STAGE=pre", "flight\r\nMXIOC_STAGE=build\nMXIOC_STAGE=unknown\n",
		strings.Repeat("a", 70), "MXIOC_STAGE=installed\n",
		"MXIOC_STAGE=service\nMXIOC_STAGE=service\nMXIOC_STAGE=installed",
	} {
		if n, err := writer.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("write: %d %v", n, err)
		}
	}
	if !reflect.DeepEqual(stages, []string{"preflight", "build", "service"}) {
		t.Fatalf("reported unexpected stages: %v", stages)
	}
}

func TestInstallLogPythonQuotedSecretsAndCarriageReturns(t *testing.T) {
	input := "progress\r\x1b[31m{\"password\":\"hidden-a\"}\x1b[0m\n" +
		"{'private_key': 'hidden-b'}\nsecret = hidden-c\napi token: hidden-d\n" +
		"{\"authorization\": \"hidden-e\"}\nhealthy service\n"
	got := redactInstallLog(input)
	for _, secret := range []string{"hidden-a", "hidden-b", "hidden-c", "hidden-d", "hidden-e", "\x1b", "\r"} {
		if strings.Contains(got, secret) {
			t.Fatal("sensitive or terminal data remained", secret)
		}
	}
	if !strings.Contains(got, "healthy service") || !strings.HasPrefix(got, "progress\n") {
		t.Fatal("ordinary diagnostics lost", got)
	}
}

func TestDiagnosticLogSanitizesBeforeBounding(t *testing.T) {
	output := strings.Repeat("safe diagnostic line\n", 5000) + "\x1b[31m{\"private_key\": \"do-not-return\"}\x1b[0m\rhealthy service\n"
	got := CleanDiagnosticLog(output)
	if len(got) > 64<<10 || strings.Contains(got, "do-not-return") || strings.Contains(got, "\x1b") || strings.Contains(got, "\r") || !strings.HasSuffix(got, "healthy service\n") {
		t.Fatal("diagnostic leak or incorrect bound")
	}
}
