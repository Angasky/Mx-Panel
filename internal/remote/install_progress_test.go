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
