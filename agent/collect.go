package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ishizakahiroshi/heartpost/report"
	"time"
)

func (r *Runner) collect(ctx context.Context, tasks []Task) (map[string]any, error) {
	results := make(map[string]any, len(tasks))
	for _, task := range tasks {
		if !task.Always && !JobEnabled(r.opts.Jobs, task.Name) {
			continue
		}
		if err := ctx.Err(); err != nil {
			if r.opts.CancelPolicy != ReportCanceled {
				return results, err
			}
			results[task.Name] = report.CollectorError(err)
			continue
		}
		value, err := task.Collect(ctx)
		if err != nil {
			r.opts.Logger.Printf("WARN: collector=%s error: %v", task.Name, err)
			results[task.Name] = report.CollectorError(err)
			continue
		}
		notes, _ := value.(interface{ CollectNotes() []string })
		if r.opts.Encoding == TypedIndented {
			raw, err := json.Marshal(value)
			if err != nil {
				results[task.Name] = report.CollectorError(err)
				continue
			}
			value = json.RawMessage(raw)
		}
		results[task.Name] = value
		r.opts.Logger.Printf("INFO: collector=%s ok", task.Name)
		if notes != nil {
			for _, note := range notes.CollectNotes() {
				r.opts.Logger.Printf("INFO: collector=%s %s", task.Name, note)
			}
		}
	}
	return results, nil
}

func (r *Runner) encode(values map[string]any) ([]byte, error) {
	return EncodePayload(r.opts.Identity, time.Now(), r.opts.Location, values, r.opts.Encoding, r.opts.MarshalFailureEmptyObject)
}

// EncodePayload preserves both the typed public encoding and sorted-key legacy
// encodings while keeping report field names and time formatting in one place.
func EncodePayload(id Identity, at time.Time, location *time.Location, values map[string]any, encoding Encoding, emptyOnFailure bool) ([]byte, error) {
	var payload any
	if encoding == TypedIndented {
		raw := make(map[string]json.RawMessage, len(values))
		for name, value := range values {
			data, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			raw[name] = data
		}
		payload = report.Build(id.ID, id.Label, id.Type, at, location, raw)
	} else {
		payload = map[string]any{"agent_id": id.ID, "agent_label": id.Label, "agent_type": id.Type, "reported_at": report.FormatTime(at, location), "collectors": values}
	}
	var body []byte
	var err error
	if encoding == SortedCompact {
		body, err = json.Marshal(payload)
	} else {
		body, err = json.MarshalIndent(payload, "", "  ")
	}
	if err != nil && emptyOnFailure {
		return []byte("{}"), nil
	}
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return body, nil
}
