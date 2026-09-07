package app

import (
	"bytes"
	"testing"

	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

// A repeated detection is a new estimate, random Manifest, real TLS execution
// and publication, never a cloned row or reassigned response. A nine-sample
// custom package keeps the two runs below the unchanged 30 target RPM limit
// and also exercises the comparison page's differing-package warning.
func exerciseRepeatedDetection(t *testing.T, p *pipelineHTTP, targetID, originalID string, original []byte, poll func(func() bool)) {
	t.Helper()
	var quote struct {
		ID           string `json:"id"`
		ManifestHash string `json:"manifest_hash"`
	}
	p.request(t, "POST", "/api/v1/runs/estimate", map[string]any{"target_id": targetID, "target_version": 1, "package": "custom", "options": map[string]any{"repetitions": 3, "probe_types": []string{"format"}, "languages": []string{"en-US"}, "max_output_levels": []int{64, 128}, "stream_modes": []bool{false}}}, 200, &quote)
	var repeated struct {
		ID, Status   string
		RequestCount int `json:"request_count"`
		Planned      int `json:"planned_samples"`
		Valid        int `json:"valid_sample_count"`
	}
	p.request(t, "POST", "/api/v1/runs", map[string]any{"estimate_id": quote.ID, "manifest_hash": quote.ManifestHash, "confirm_cost": true}, 202, &repeated)
	if repeated.ID == "" || repeated.ID == originalID || repeated.Planned != 9 {
		t.Fatal("repeated detection did not create a distinct bounded custom Run")
	}
	path := "/api/v1/runs/" + repeated.ID
	poll(func() bool {
		p.request(t, "GET", path, nil, 200, &repeated)
		if repeated.Status == "FAILED" || repeated.Status == "CANCELLED" {
			t.Fatal("controlled repeated TLS detection failed")
		}
		return repeated.Status == "COMPLETED" || repeated.Status == "PARTIAL" || repeated.Status == "REVIEW_REQUIRED"
	})
	var result runservice.ResultView
	p.request(t, "GET", path+"/result?analysis_revision=1", nil, 200, &result)
	if result.RunID != repeated.ID || result.ExpectedSamples != 9 || result.ValidSamples < 1 || repeated.RequestCount != 9 || repeated.Valid < result.ValidSamples {
		t.Fatal("repeated detection lost actual requests or independent published samples")
	}
	if !bytes.Equal(original, p.request(t, "GET", "/api/v1/runs/"+originalID+"/result?analysis_revision=1", nil, 200, nil)) {
		t.Fatal("new detection mutated the first immutable result")
	}
	var history struct {
		Items []runservice.HistoryItem `json:"items"`
	}
	p.request(t, "GET", "/api/v1/runs?target_id="+targetID, nil, 200, &history)
	if len(history.Items) != 2 || history.Items[0].ID != repeated.ID || history.Items[1].ID != originalID || history.Items[0].Result == nil || history.Items[1].Result == nil {
		t.Fatal("target history did not retain both distinct published detections")
	}
	exerciseActualRunTrends(t, p, targetID, originalID, repeated.ID)
}
