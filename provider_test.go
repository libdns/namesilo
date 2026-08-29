package namesilo

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

var (
	APIToken = os.Getenv("LIBDNS_NAMESILO_TOKEN")
	zone     = os.Getenv("LIBDNS_NAMESILO_ZONE")
)

var (
	record0, _ = libdns.RR{
		Type: "CNAME",
		Name: "test898008",
		Data: "wikipedia.com",
	}.Parse()
	record0Changed, _ = libdns.RR{
		Type: record0.RR().Type,
		Name: record0.RR().Name,
		Data: "google.com",
	}.Parse()
	record1, _ = libdns.RR{
		Type: "CNAME",
		Name: "test289808",
		Data: "wikipedia.com",
	}.Parse()
	record2, _ = libdns.RR{
		Type: "CNAME",
		Name: "test652753",
		Data: "wikipedia.com",
	}.Parse()
)

var initialNumberOfRecords = 0

func TestAppendRecords(t *testing.T) {

	provider := Provider{APIToken: APIToken}

	ctx := context.Background()

	initialRecords, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Errorf("%v", err)
	}
	initialNumberOfRecords = len(initialRecords)

	newRecords := []libdns.Record{record0, record1}

	records, err := provider.AppendRecords(ctx, zone, newRecords)
	if err != nil {
		t.Errorf("%v", err)
	}

	if len(newRecords) != len(records) {
		t.Errorf("Number of appended records does not match number of records")
	}
}

func TestGetRecords(t *testing.T) {

	provider := Provider{APIToken: APIToken}

	ctx := context.Background()

	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Errorf("%v", err)
	}

	if len(records) != initialNumberOfRecords+2 {
		t.Errorf("invalid number of records: expected %d, got %d", initialNumberOfRecords+2, len(records))
	}
}

func TestSetRecords(t *testing.T) {
	provider := Provider{APIToken: APIToken}

	ctx := context.Background()

	changedRecords := []libdns.Record{record0Changed, record2}

	records, err := provider.SetRecords(ctx, zone, changedRecords)
	if err != nil {
		t.Fatalf("appending records failed: %v", err)
	}

	if len(changedRecords) != len(records) {
		t.Fatalf("Number of appended records does not match number of records")
	}
}

func TestDeleteRecords(t *testing.T) {

	provider := Provider{APIToken: APIToken}

	ctx := context.Background()

	deletedRecords := []libdns.Record{record0Changed, record1, record2}

	records, err := provider.DeleteRecords(ctx, zone, deletedRecords)
	if err != nil {
		t.Errorf("deleting records failed: %v", err)
	}

	if len(deletedRecords) != len(records) {
		t.Errorf("Number of deleted records does not match number of records")
	}

	finalRecords, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Errorf("%v", err)
	}

	if len(finalRecords) != initialNumberOfRecords {
		t.Errorf("invalid number of records: expected %d, got %d", initialNumberOfRecords, len(finalRecords))
	}
}

// TestTrailingDotTargets verifies that records with trailing dots in hostname
// targets (standard libdns FQDN format) are accepted by the Namesilo API.
// Uses random subdomain names to avoid conflicts with existing or leftover records.
func TestTrailingDotTargets(t *testing.T) {
	if APIToken == "" || zone == "" {
		t.Skip("LIBDNS_NAMESILO_TOKEN and LIBDNS_NAMESILO_ZONE required")
	}

	provider := Provider{APIToken: APIToken}
	ctx := context.Background()
	ttl := 3600 * time.Second

	// Random suffix to avoid collisions with leftover records from prior runs.
	rnd := int(time.Now().UnixMilli() % 100000)

	// Records with trailing dots in their hostname targets.
	cnameWithDot, _ := libdns.RR{
		Type: "CNAME",
		Name: fmt.Sprintf("libdns-test-%d-cname", rnd),
		Data: "wikipedia.com.",
		TTL:  ttl,
	}.Parse()
	mxWithDot, _ := libdns.RR{
		Type: "MX",
		Name: fmt.Sprintf("libdns-test-%d-mx", rnd),
		Data: "10 mail.example.com.",
		TTL:  ttl,
	}.Parse()
	srvWithDot, _ := libdns.RR{
		Type: "SRV",
		Name: fmt.Sprintf("libdns-test-%d-srv._tcp", rnd),
		Data: "10 5 993 target.example.com.",
		TTL:  ttl,
	}.Parse()

	testRecords := []libdns.Record{cnameWithDot, mxWithDot, srvWithDot}

	// Cleanup on exit.
	t.Cleanup(func() {
		provider.DeleteRecords(ctx, zone, testRecords)
	})

	// Phase 1: Append all records with trailing dots.
	appended, err := provider.AppendRecords(ctx, zone, testRecords)
	if err != nil {
		t.Fatalf("AppendRecords with trailing dots: %v", err)
	}
	if len(appended) != len(testRecords) {
		t.Fatalf("expected %d appended, got %d", len(testRecords), len(appended))
	}

	// Phase 2: Verify records exist.
	got, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	for _, want := range testRecords {
		rr := want.RR()
		found := false
		for _, g := range got {
			grr := g.RR()
			if grr.Type == rr.Type && grr.Name == rr.Name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s %s not found after append", rr.Type, rr.Name)
		}
	}

	// Phase 3: Delete all records.
	deleted, err := provider.DeleteRecords(ctx, zone, testRecords)
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if len(deleted) != len(testRecords) {
		t.Errorf("expected %d deleted, got %d", len(testRecords), len(deleted))
	}
}
