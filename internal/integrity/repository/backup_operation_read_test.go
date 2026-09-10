package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestBackupOperationReadPureBoundsAndClosedViews(t *testing.T) {
	for _, request := range []BackupOperationListRequest{{-1, 1}, {0, 0}, {0, 101}, {0, -1}} {
		if validBackupOperationListRequest(request) {
			t.Fatal("unbounded request")
		}
		if page, err := (*Store)(nil).ListBackupOperations(t.Context(), ManagementAuthority{}, request); !errors.Is(err, ErrConfiguration) || !reflect.DeepEqual(page, BackupOperationPage{}) {
			t.Fatal("configuration returned page", err)
		}
	}
	for _, request := range []BackupOperationListRequest{{0, 1}, {0, 100}, {9223372036854775807, 100}} {
		if !validBackupOperationListRequest(request) {
			t.Fatal("legal typed keyset")
		}
	}
	if view, err := (*Store)(nil).ReadBackupOperation(context.Background(), ManagementAuthority{}, 1); !errors.Is(err, ErrConfiguration) || view != (BackupOperationView{}) {
		t.Fatal("nil store")
	}
	marker := "never-automatically-serialize-state"
	for _, value := range []any{BackupOperationView{ReasonCode: marker}, BackupOperationPage{Items: []BackupOperationView{{ReasonCode: marker}}}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(verb, value), marker) {
				t.Fatal("fmt leak")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("HTTP DTO mapping bypass")
		}
		if _, err := yaml.Marshal(value); err == nil {
			t.Fatal("YAML mapping bypass")
		}
		var log bytes.Buffer
		slog.New(slog.NewJSONHandler(&log, nil)).Info("state", "value", value)
		if strings.Contains(log.String(), marker) {
			t.Fatal("log leak")
		}
	}
	if err := json.Unmarshal([]byte(`{}`), &BackupOperationView{}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("view input accepted")
	}
	if err := json.Unmarshal([]byte(`{}`), &BackupOperationPage{}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("page input accepted")
	}
}
