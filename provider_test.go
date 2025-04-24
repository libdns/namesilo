package namesilo

import (
	"context"
	"os"
	"testing"

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
