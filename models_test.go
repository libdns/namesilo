package namesilo

import (
	"encoding/json"
	"testing"
)

// Namesilo may send resource_record as a bare object, not a one-element array,
// which a plain []record cannot decode. A one-record zone sends an array today.
func TestRecordListUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    []record
		wantErr bool
	}{
		{
			name: "single record encoded as an object",
			body: `{"reply":{"code":300,"detail":"success","resource_record":{"record_id":"1a2b3c4d5e6f","type":"A","host":"test.namesilo.com","value":"55.55.55.55","ttl":"7207","distance":"0"}}}`,
			want: []record{
				{ID: "1a2b3c4d5e6f", Type: "A", Host: "test.namesilo.com", Value: "55.55.55.55", TTL: 7207, Distance: 0},
			},
		},
		{
			name: "multiple records encoded as an array",
			body: `{"reply":{"code":300,"detail":"success","resource_record":[{"record_id":"1a2b3c4d5e6f","type":"A","host":"test.namesilo.com","value":"55.55.55.55","ttl":"7207","distance":"0"},{"record_id":"fH35aH4hsv","type":"MX","host":"namesilo.com","value":"mail.namesilo.com","ttl":"7207","distance":"10"}]}}`,
			want: []record{
				{ID: "1a2b3c4d5e6f", Type: "A", Host: "test.namesilo.com", Value: "55.55.55.55", TTL: 7207, Distance: 0},
				{ID: "fH35aH4hsv", Type: "MX", Host: "namesilo.com", Value: "mail.namesilo.com", TTL: 7207, Distance: 10},
			},
		},
		{
			name: "zone with no records omits the field",
			body: `{"reply":{"code":300,"detail":"success"}}`,
			want: nil,
		},
		{
			name: "explicit null",
			body: `{"reply":{"code":300,"detail":"success","resource_record":null}}`,
			want: nil,
		},
		{
			name:    "unexpected shape is still an error",
			body:    `{"reply":{"code":300,"detail":"success","resource_record":"nope"}}`,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var resp namesiloResponse
			if err := json.Unmarshal([]byte(test.body), &resp); err != nil {
				t.Fatalf("decoding reply: %v", err)
			}

			// Mirror the guard in doAPIRequest: an absent field is never decoded.
			var got recordList
			var err error
			if len(resp.Reply.ResourceRecord) > 0 {
				err = json.Unmarshal(resp.Reply.ResourceRecord, &got)
			}
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decoding resource_record: %v", err)
			}

			if len(got) != len(test.want) {
				t.Fatalf("expected %d records, got %d: %+v", len(test.want), len(got), got)
			}
			for i := range test.want {
				if got[i] != test.want[i] {
					t.Errorf("record %d: expected %+v, got %+v", i, test.want[i], got[i])
				}
			}
		})
	}
}

// An absent resource_record leaves the raw message empty; doAPIRequest checks.
func TestRecordListEmptyRawMessage(t *testing.T) {
	var resp namesiloResponse
	if err := json.Unmarshal([]byte(`{"reply":{"code":300,"detail":"success"}}`), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Reply.ResourceRecord) != 0 {
		t.Errorf("expected an empty raw message, got %q", resp.Reply.ResourceRecord)
	}
}

func TestNamesiloRecordMX(t *testing.T) {
	in := record{ID: "fH35aH4hsv", Type: "MX", Host: "namesilo.com", Value: "mail.namesilo.com", TTL: 7207, Distance: 10}

	libdnsRecord, err := in.toLibDNS("namesilo.com.")
	if err != nil {
		t.Fatalf("converting to libdns: %v", err)
	}

	got, err := namesiloRecord("namesilo.com.", libdnsRecord)
	if err != nil {
		t.Fatalf("converting from libdns: %v", err)
	}

	if got.Value != "mail.namesilo.com" {
		t.Errorf("expected value %q, got %q", "mail.namesilo.com", got.Value)
	}
	if got.Distance != 10 {
		t.Errorf("expected distance 10, got %d", got.Distance)
	}
	if got.Host != "" {
		t.Errorf("expected an empty host for the zone apex, got %q", got.Host)
	}
}
