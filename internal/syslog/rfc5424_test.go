package syslog

import (
	"strings"
	"testing"
)

func TestStampNilSD(t *testing.T) {
	msg := "<34>1 2024-01-01T12:00:00Z host app 1234 - - hello world"
	out := string(StampSyslogMessage([]byte(msg), 42))
	if !strings.Contains(out, `[tenant@42 tenant-id="42"]`) {
		t.Fatalf("expected tenant SD-ID injected, got: %s", out)
	}
	if !strings.HasSuffix(out, " hello world") {
		t.Fatalf("MSG must be preserved, got: %s", out)
	}
	if !strings.HasPrefix(out, "<34>1") {
		t.Fatalf("PRI/VERSION must be preserved, got: %s", out)
	}
}

func TestStampReplaceExistingTenantSD(t *testing.T) {
	// SD directly after MSGID (no "-" marker): tenant block + origin block
	msg := `<34>1 2024-01-01T12:00:00Z host app 1234 [tenant@999 tenant-id="victim"][origin@123 sw="1.0"] payload`
	out := string(StampSyslogMessage([]byte(msg), 42))
	if strings.Contains(out, `tenant@999`) {
		t.Fatalf("old tenant SD-ID must be removed, got: %s", out)
	}
	if !strings.Contains(out, `[tenant@42 tenant-id="42"]`) {
		t.Fatalf("fresh tenant SD-ID must be present, got: %s", out)
	}
	if !strings.Contains(out, `[origin@123 sw="1.0"]`) {
		t.Fatalf("non-tenant SD-ID must be preserved, got: %s", out)
	}
	if !strings.HasSuffix(out, " payload") {
		t.Fatalf("MSG must be preserved, got: %s", out)
	}
}

func TestStampPreserveOtherSDIDs(t *testing.T) {
	msg := `<34>1 2024-01-01T12:00:00Z host app 1234 - [origin@123 sw="1.0"] body`
	out := string(StampSyslogMessage([]byte(msg), 42))
	if !strings.Contains(out, `[origin@123 sw="1.0"]`) {
		t.Fatalf("origin SD-ID must be preserved, got: %s", out)
	}
	if !strings.Contains(out, `[tenant@42 tenant-id="42"]`) {
		t.Fatalf("tenant SD-ID must be added, got: %s", out)
	}
}

func TestStampMalformedPriority(t *testing.T) {
	msg := "<abc rest of message"
	out := StampSyslogMessage([]byte(msg), 42)
	if string(out) != msg {
		t.Fatalf("malformed PRI must be returned unchanged, got: %s", out)
	}
}

func TestStampShortMessage(t *testing.T) {
	msg := "<1>1"
	out := StampSyslogMessage([]byte(msg), 42)
	if string(out) != msg {
		t.Fatalf("short message must be returned unchanged, got: %s", out)
	}
}

func TestStampMultipleTenantSDs(t *testing.T) {
	msg := `<34>1 2024-01-01T12:00:00Z host app 1234 [tenant@1 id="a"][tenant@2 id="b"][origin@9 ok="1"] data`
	out := string(StampSyslogMessage([]byte(msg), 42))
	if strings.Contains(out, "tenant@1") || strings.Contains(out, "tenant@2") {
		t.Fatalf("all old tenant SD-IDs must be removed, got: %s", out)
	}
	if !strings.Contains(out, `[tenant@42 tenant-id="42"]`) {
		t.Fatalf("fresh tenant SD-ID must be present, got: %s", out)
	}
	if !strings.Contains(out, `[origin@9 ok="1"]`) {
		t.Fatalf("origin SD-ID must be preserved, got: %s", out)
	}
}

func TestStampRealWorldSyslog(t *testing.T) {
	// Realistic sshd message with no structured data
	msg := `<34>1 2024-06-15T08:30:00+02:00 webserver-01 sshd 1234 - Failed password for invalid user admin from 203.0.113.5 port 22 ssh2`
	out := string(StampSyslogMessage([]byte(msg), 7))
	if !strings.Contains(out, `[tenant@7 tenant-id="7"]`) {
		t.Fatalf("expected tenant SD-ID, got: %s", out)
	}
	if !strings.Contains(out, "Failed password for invalid user admin") {
		t.Fatalf("MSG must be preserved, got: %s", out)
	}
	if !strings.Contains(out, "webserver-01 sshd 1234") {
		t.Fatalf("HOSTNAME/APP-NAME/PROCID must be preserved, got: %s", out)
	}
}

func TestStampEmptyInput(t *testing.T) {
	out := StampSyslogMessage([]byte(""), 42)
	if len(out) != 0 {
		t.Fatalf("expected empty output, got %q", out)
	}
}
