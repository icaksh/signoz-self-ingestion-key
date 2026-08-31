package syslog

import (
	"strings"
	"testing"
)

func TestStampNilSD(t *testing.T) {
	in := []byte("<13>1 2026-01-15T10:00:00Z host app 123 ID - hello world")
	out := StampSyslogMessage(in, 42, "acme")
	got := string(out)
	if !strings.Contains(got, `[tenant@42 tenant-id="42"]`) {
		t.Errorf("tenant SD not injected: %s", got)
	}
	if !strings.HasSuffix(got, "[42][acme] hello world") {
		t.Errorf("body prefix/message lost: %s", got)
	}
	// MSGID must be preserved (the legacy code dropped it).
	if !strings.Contains(got, "app 123 ID") {
		t.Errorf("header/MSGID lost: %s", got)
	}
}

func TestStampReplacesTenantSD(t *testing.T) {
	in := []byte(`<13>1 2026-01-15T10:00:00Z host app 123 ID [tenant@99 tenant-id="99"] hello`)
	out := StampSyslogMessage(in, 7, "acme")
	got := string(out)
	if strings.Contains(got, "tenant@99") {
		t.Errorf("client tenant SD not stripped: %s", got)
	}
	if !strings.Contains(got, `[tenant@7 tenant-id="7"]`) {
		t.Errorf("server tenant SD missing: %s", got)
	}
}

func TestStampPreservesOtherSDIDs(t *testing.T) {
	in := []byte(`<13>1 2026-01-15T10:00:00Z host app 123 ID [origin@123 ip="1.2.3.4"] hello`)
	out := StampSyslogMessage(in, 5, "acme")
	got := string(out)
	if !strings.Contains(got, `[origin@123 ip="1.2.3.4"]`) {
		t.Errorf("other SD-ID lost: %s", got)
	}
	if !strings.Contains(got, `[tenant@5 tenant-id="5"]`) {
		t.Errorf("tenant SD missing: %s", got)
	}
}

func TestStampMultipleTenantSDsStripped(t *testing.T) {
	in := []byte(`<13>1 2026-01-15T10:00:00Z host app 123 ID [tenant@1 tenant-id="1"][tenant@2 tenant-id="2"] hi`)
	out := StampSyslogMessage(in, 3, "acme")
	got := string(out)
	if strings.Contains(got, "tenant@1") || strings.Contains(got, "tenant@2") {
		t.Errorf("client tenant SDs not stripped: %s", got)
	}
	if !strings.Contains(got, `[tenant@3 tenant-id="3"]`) {
		t.Errorf("server tenant SD missing: %s", got)
	}
}

func TestStampMalformedUnchanged(t *testing.T) {
	for _, in := range []string{"", "no pri", "<13> short", "<13>1 2026-01-15T10:00:00Z host"} {
		out := StampSyslogMessage([]byte(in), 1, "acme")
		if string(out) != in {
			t.Errorf("malformed %q changed to %q", in, out)
		}
	}
}
