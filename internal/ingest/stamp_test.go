package ingest

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	logscollector "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	tracecollector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

func traceRequestWithAttrs(attrs ...*commonv1.KeyValue) *tracecollector.ExportTraceServiceRequest {
	return &tracecollector.ExportTraceServiceRequest{
		ResourceSpans: []*tracev1.ResourceSpans{
			{Resource: &resourcev1.Resource{Attributes: attrs}},
		},
	}
}

func strKV(key, value string) *commonv1.KeyValue {
	return &commonv1.KeyValue{
		Key:   key,
		Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: value}},
	}
}

func protojsonMarshal(m proto.Message) ([]byte, error) {
	return protojson.Marshal(m)
}

func protojsonUnmarshal(b []byte, m proto.Message) error {
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(b, m)
}

func hasAttr(res *resourcev1.Resource, key, value string) bool {
	for _, kv := range res.Attributes {
		if kv.Key == key && kv.Value.GetStringValue() == value {
			return true
		}
	}
	return false
}

func TestStampStripsClientTenantAttrs(t *testing.T) {
	req := traceRequestWithAttrs(
		strKV("tenant.id", "attacker"),
		strKV("tenant.name", "evil"),
		strKV("service.namespace", "spoofed"),
		strKV("service.name", "keep-me"),
	)

	stampResources(req, "42", "acme")

	res := req.ResourceSpans[0].Resource
	if hasAttr(res, "tenant.id", "attacker") || hasAttr(res, "tenant.name", "evil") || hasAttr(res, "service.namespace", "spoofed") {
		t.Fatalf("client-claimed attributes not stripped")
	}
	if !hasAttr(res, "tenant.id", "42") {
		t.Errorf("server tenant.id not injected")
	}
	if !hasAttr(res, "tenant.name", "acme") {
		t.Errorf("server tenant.name not injected")
	}
	if !hasAttr(res, "service.name", "keep-me") {
		t.Errorf("unrelated attribute removed")
	}
}

func TestStampNilResourceAllocates(t *testing.T) {
	req := &tracecollector.ExportTraceServiceRequest{
		ResourceSpans: []*tracev1.ResourceSpans{{Resource: nil}},
	}
	stampResources(req, "7", "n")
	res := req.ResourceSpans[0].Resource
	if res == nil || !hasAttr(res, "tenant.id", "7") {
		t.Fatalf("nil resource not stamped")
	}
}

func TestStampProtoRoundTrip(t *testing.T) {
	req := traceRequestWithAttrs(strKV("tenant.id", "bad"))
	raw, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	out, err := stampTenantIdentity(raw, "application/x-protobuf", "", "traces", "9", "acme")
	if err != nil {
		t.Fatal(err)
	}
	var decoded tracecollector.ExportTraceServiceRequest
	if err := proto.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if !hasAttr(decoded.ResourceSpans[0].Resource, "tenant.id", "9") {
		t.Errorf("proto round-trip lost stamp")
	}
}

func TestStampJSONRoundTrip(t *testing.T) {
	req := traceRequestWithAttrs(strKV("tenant.id", "bad"))
	raw, err := protojsonMarshal(req)
	if err != nil {
		t.Fatal(err)
	}
	out, err := stampTenantIdentity(raw, "application/json; charset=utf-8", "", "traces", "9", "acme")
	if err != nil {
		t.Fatal(err)
	}
	var decoded tracecollector.ExportTraceServiceRequest
	if err := protojsonUnmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if !hasAttr(decoded.ResourceSpans[0].Resource, "tenant.id", "9") {
		t.Errorf("json round-trip lost stamp")
	}
}

func TestStampGzipRoundTrip(t *testing.T) {
	req := traceRequestWithAttrs(strKV("tenant.id", "bad"))
	raw, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzipBytes(raw)

	out, err := stampTenantIdentity(gz, "application/x-protobuf", "gzip", "traces", "5", "acme")
	if err != nil {
		t.Fatal(err)
	}
	plain := gunzipBytes(t, out)
	var decoded tracecollector.ExportTraceServiceRequest
	if err := proto.Unmarshal(plain, &decoded); err != nil {
		t.Fatal(err)
	}
	if !hasAttr(decoded.ResourceSpans[0].Resource, "tenant.id", "5") {
		t.Errorf("gzip round-trip lost stamp")
	}
}

func TestStampLogBodyPrefixed(t *testing.T) {
	req := &logscollector.ExportLogsServiceRequest{
		ResourceLogs: []*logsv1.ResourceLogs{
			{
				ScopeLogs: []*logsv1.ScopeLogs{
					{
						LogRecords: []*logsv1.LogRecord{
							{Body: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: "hello world"}}},
							{Body: &commonv1.AnyValue{Value: &commonv1.AnyValue_IntValue{IntValue: 42}}},
							{Body: nil},
						},
					},
				},
			},
		},
	}

	stampResources(req, "12", "acme")

	records := req.ResourceLogs[0].ScopeLogs[0].LogRecords
	if got := records[0].Body.GetStringValue(); got != "[12][acme] hello world" {
		t.Errorf("string body not prefixed: %q", got)
	}
	if got := records[1].Body.GetIntValue(); got != 42 {
		t.Errorf("non-string body was mutated: %v", got)
	}
	if records[2].Body != nil {
		t.Errorf("nil body was allocated")
	}
}

func TestStampMalformedBody(t *testing.T) {
	if _, err := stampTenantIdentity([]byte("not valid"), "application/x-protobuf", "", "traces", "1", "n"); err == nil {
		t.Errorf("expected error for malformed body")
	}
	if _, err := stampTenantIdentity([]byte("not gzip"), "application/x-protobuf", "gzip", "traces", "1", "n"); err == nil {
		t.Errorf("expected error for bad gzip")
	}
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func gunzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
