package namesilo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

type intString int

func (i *intString) UnmarshalJSON(data []byte) error {
	number, err := strconv.Atoi(strings.Trim(string(data), "\""))
	*i = intString(number)
	return err
}

type record struct {
	ID       string    `json:"record_id"`
	Type     string    `json:"type"`
	Host     string    `json:"host"`
	Value    string    `json:"value"`
	TTL      intString `json:"ttl"`
	Distance intString `json:"distance,omitempty"`
}

// recordList holds resource_record entries, which Namesilo may send as a bare
// object instead of a one-element array (caddy-dns/namesilo#5), or omit if empty.
type recordList []record

func (l *recordList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)

	if len(data) > 0 && data[0] == '{' {
		var single record
		if err := json.Unmarshal(data, &single); err != nil {
			return err
		}
		*l = recordList{single}
		return nil
	}

	var multiple []record
	if err := json.Unmarshal(data, &multiple); err != nil {
		return err
	}
	*l = multiple
	return nil
}

// splitTriplet splits a Namesilo "X:Y:Z" value, where Z may contain colons.
func splitTriplet(recordType, value string) (string, string, string, error) {
	parts := strings.SplitN(value, ":", 3)
	if expectedParts := 3; len(parts) != expectedParts {
		return "", "", "", fmt.Errorf("malformed %s value %q; expected %d colon-separated parts", recordType, value, expectedParts)
	}
	return parts[0], parts[1], parts[2], nil
}

func (n record) toLibDNS(zone string) (libdns.Record, error) {
	// Namesilo keeps preference and priority in a separate field and stores CAA
	// and SRV values in its own colon form; rebuild what libdns expects.
	switch n.Type {
	case "MX":
		n.Value = fmt.Sprintf("%d %s", n.Distance, n.Value)
	case "CAA":
		flags, tag, value, err := splitTriplet(n.Type, n.Value)
		if err != nil {
			return nil, err
		}
		n.Value = fmt.Sprintf("%s %s %q", flags, tag, value)
	case "SRV":
		weight, port, target, err := splitTriplet(n.Type, n.Value)
		if err != nil {
			return nil, err
		}
		n.Value = fmt.Sprintf("%d %s %s %s", n.Distance, weight, port, target)
	}

	return libdns.RR{
		Type: n.Type,
		Name: libdns.RelativeName(n.Host, zone),
		Data: n.Value,
		TTL:  time.Duration(n.TTL) * time.Second,
	}.Parse()
}

func namesiloRecord(zone string, r libdns.Record) (record, error) {
	rr := r.RR()

	value := rr.Data
	distance := 0
	switch rr.Type {
	case "MX":
		fields := strings.Fields(rr.Data)
		if expectedFields := 2; len(fields) != expectedFields {
			return record{}, fmt.Errorf("expected data to contain %d fields, but had %d", expectedFields, len(fields))
		}
		value = fields[1]
		convertedDistance, err := strconv.Atoi(fields[0])
		if err != nil {
			return record{}, fmt.Errorf("parsing MX preference %q: %v", fields[0], err)
		}
		distance = convertedDistance
	case "CAA":
		fields := strings.Fields(rr.Data)
		if expectedFields := 3; len(fields) != expectedFields {
			return record{}, fmt.Errorf("expected data to contain %d fields, but had %d", expectedFields, len(fields))
		}
		// Namesilo rejects a value holding a colon, so iodef cannot be stored.
		value = fmt.Sprintf("%s:%s:%s", fields[0], fields[1], strings.Trim(fields[2], `"`))
	case "SRV":
		fields := strings.Fields(rr.Data)
		if expectedFields := 4; len(fields) != expectedFields {
			return record{}, fmt.Errorf("expected data to contain %d fields, but had %d", expectedFields, len(fields))
		}
		convertedPriority, err := strconv.Atoi(fields[0])
		if err != nil {
			return record{}, fmt.Errorf("parsing SRV priority %q: %v", fields[0], err)
		}
		distance = convertedPriority
		value = fmt.Sprintf("%s:%s:%s", fields[1], fields[2], fields[3])
	}

	host := rr.Name
	if host == "@" {
		host = ""
	}

	return record{
		Type:     rr.Type,
		Host:     host,
		TTL:      intString(rr.TTL.Seconds()),
		Value:    value,
		Distance: intString(distance),
	}, nil
}

type namesiloResponse struct {
	Reply struct {
		Code           int             `json:"code"`
		Detail         string          `json:"detail"`
		ResourceRecord json.RawMessage `json:"resource_record,omitempty"`
	}
}
