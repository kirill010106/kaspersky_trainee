package generated_test

import (
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/kirill010106/kaspersky_trainee/internal/httpapi/generated"
)

func TestThreatUpdateJSONV2(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantErr         bool
		wantDescription *string
	}{
		{
			name: "description omitted",
			body: `{"name":"Trojan","type":"trojan","severity":"high"}`,
		},
		{
			name:            "description empty",
			body:            `{"name":"Trojan","type":"trojan","severity":"high","description":""}`,
			wantDescription: new(""),
		},
		{
			name:            "description provided",
			body:            `{"name":"Trojan","type":"trojan","severity":"high","description":"Details"}`,
			wantDescription: new("Details"),
		},
		{
			name:    "unknown field",
			body:    `{"name":"Trojan","type":"trojan","severity":"high","extra":true}`,
			wantErr: true,
		},
		{
			name:    "md5 forbidden in update",
			body:    `{"name":"Trojan","type":"trojan","severity":"high","md5":"d41d8cd98f00b204e9800998ecf8427e"}`,
			wantErr: true,
		},
		{
			name:    "wrong field casing",
			body:    `{"Name":"Trojan","type":"trojan","severity":"high"}`,
			wantErr: true,
		},
		{
			name:    "duplicate field",
			body:    `{"name":"Trojan","name":"Other","type":"trojan","severity":"high"}`,
			wantErr: true,
		},
		{
			name:    "invalid utf8",
			body:    "{\"name\":\"\xff\",\"type\":\"trojan\",\"severity\":\"high\"}",
			wantErr: true,
		},
		{
			name:    "second json value",
			body:    `{"name":"Trojan","type":"trojan","severity":"high"} {}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got generated.ThreatUpdateRequest

			err := json.Unmarshal(
				[]byte(tt.body),
				&got,
				json.RejectUnknownMembers(true),
			)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Unmarshal() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if got.Name != "Trojan" ||
				got.Type != generated.Trojan ||
				got.Severity != generated.High {
				t.Fatalf("unexpected decoded request: %+v", got)
			}

			if tt.wantDescription == nil {
				if got.Description != nil {
					t.Fatalf("description = %q, want nil", *got.Description)
				}
			} else if got.Description == nil ||
				*got.Description != *tt.wantDescription {
				t.Fatalf("description does not match %q", *tt.wantDescription)
			}
		})
	}
}

func TestThreatResponseJSONV2(t *testing.T) {
	now := time.Date(2026, time.October, 27, 12, 0, 0, 0, time.UTC)

	response := generated.ThreatResponse{
		Md5:         "d41d8cd98f00b204e9800998ecf8427e",
		Name:        "Trojan",
		Description: "",
		Type:        generated.Trojan,
		Severity:    generated.High,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var fields map[string]string
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("decode response fields: %v", err)
	}

	required := []string{
		"md5", "name", "description", "type",
		"severity", "created_at", "updated_at",
	}
	if len(fields) != len(required) {
		t.Fatalf("response has %d fields, want %d: %s",
			len(fields), len(required), data)
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			t.Errorf("missing response field %q", name)
		}
	}

	if fields["description"] != "" {
		t.Errorf("description = %q, want empty string", fields["description"])
	}
	for _, name := range []string{"created_at", "updated_at"} {
		if fields[name] != now.Format(time.RFC3339) {
			t.Errorf("%s = %q, want %q",
				name, fields[name], now.Format(time.RFC3339))
		}
	}
}
