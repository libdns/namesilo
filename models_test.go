package namesilo

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/libdns/libdns"
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

// A bad MX preference must error, not yield a zero record with a nil error.
func TestNamesiloRecordMXBadPreference(t *testing.T) {
	rr := libdns.RR{Type: "MX", Name: "@", Data: "abc mail.namesilo.com", TTL: 7207 * time.Second}

	if _, err := namesiloRecord("namesilo.com.", rr); err == nil {
		t.Fatal("expected an error for a non-numeric MX preference")
	}
}

// Namesilo stores CAA and SRV values in its own colon form and keeps the SRV
// priority in distance, so both need converting each way.
func TestCAAandSRVConversion(t *testing.T) {
	tests := []struct {
		name       string
		namesilo   record
		libdnsData string
	}{
		{
			name:       "CAA issue",
			namesilo:   record{ID: "1", Type: "CAA", Host: "@", Value: "0:issue:letsencrypt.org", TTL: 3600},
			libdnsData: `0 issue "letsencrypt.org"`,
		},
		{
			name:       "CAA issuewild with a non-zero flag",
			namesilo:   record{ID: "2", Type: "CAA", Host: "@", Value: "128:issuewild:letsencrypt.org", TTL: 3600},
			libdnsData: `128 issuewild "letsencrypt.org"`,
		},
		{
			name:       "SRV keeps its priority in distance",
			namesilo:   record{ID: "3", Type: "SRV", Host: "_sip._tcp", Value: "5:5060:sip.example.com", TTL: 3600, Distance: 10},
			libdnsData: "10 5 5060 sip.example.com",
		},
		{
			name:       "SRV with priority zero",
			namesilo:   record{ID: "4", Type: "SRV", Host: "_sip._tcp", Value: "5:5060:sip.example.com", TTL: 3600, Distance: 0},
			libdnsData: "0 5 5060 sip.example.com",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			libdnsRecord, err := test.namesilo.toLibDNS("example.com.")
			if err != nil {
				t.Fatalf("converting to libdns: %v", err)
			}
			if got := libdnsRecord.RR().Data; got != test.libdnsData {
				t.Errorf("expected data %q, got %q", test.libdnsData, got)
			}

			// and back again
			got, err := namesiloRecord("example.com.", libdnsRecord)
			if err != nil {
				t.Fatalf("converting from libdns: %v", err)
			}
			if got.Value != test.namesilo.Value {
				t.Errorf("expected value %q, got %q", test.namesilo.Value, got.Value)
			}
			if got.Distance != test.namesilo.Distance {
				t.Errorf("expected distance %d, got %d", test.namesilo.Distance, got.Distance)
			}
			if got.Type != test.namesilo.Type {
				t.Errorf("expected type %q, got %q", test.namesilo.Type, got.Type)
			}
		})
	}
}

// A value Namesilo could not have stored should error here, not inside libdns.
func TestCAAandSRVMalformedValues(t *testing.T) {
	for _, rec := range []record{
		{Type: "CAA", Host: "@", Value: "0 issue letsencrypt.org", TTL: 3600},
		{Type: "SRV", Host: "_sip._tcp", Value: "5060:sip.example.com", TTL: 3600},
	} {
		if _, err := rec.toLibDNS("example.com."); err == nil {
			t.Errorf("%s: expected an error for value %q", rec.Type, rec.Value)
		}
	}
}
