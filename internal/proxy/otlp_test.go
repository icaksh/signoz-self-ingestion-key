package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	logscollector "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	metricscollector "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	tracecollector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

func makeTraceRequest(attrs ...*commonv1.KeyValue) *tracecollector.ExportTraceServiceRequest {
	return &tracecollector.ExportTraceServiceRequest{
		ResourceSpans: []*tracev1.ResourceSpans{{
			Resource: &resourcev1.Resource{
				Attributes: attrs,
			},
			ScopeSpans: []*tracev1.ScopeSpans{{
				Spans: []*tracev1.Span{{
					Name:              "test-span",
					TraceId:           make([]byte, 16),
					SpanId:            make([]byte, 8),
					StartTimeUnixNano: 1000,
					EndTimeUnixNano:   2000,
					Attributes: []*commonv1.KeyValue{
						{Key: "http.method", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: "GET"}}},
					},
				}},
			}},
		}},
	}
}

func stringAttr(key, val string) *commonv1.KeyValue {
	return &commonv1.KeyValue{
		Key:   key,
		Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: val}},
	}
}

func TestStampTenantIdentityProtoTraces(t *testing.T) {
	req := makeTraceRequest(
		stringAttr("tenant.id", "victim"),
		stringAttr("service.name", "myapp"),
		stringAttr("service.namespace", "evil"),
	)
	rawBody, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	stampedBody, err := stampTenantIdentity(rawBody, "application/x-protobuf", "", "traces", "42", "real-tenant")
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}

	var result tracecollector.ExportTraceServiceRequest
	if err := proto.Unmarshal(stampedBody, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	rs := result.ResourceSpans[0]
	attrs := make(map[string]string)
	for _, kv := range rs.Resource.Attributes {
		attrs[kv.Key] = kv.Value.GetStringValue()
	}

	if attrs["tenant.id"] != "42" {
		t.Fatalf("expected tenant.id=42, got %q", attrs["tenant.id"])
	}
	if attrs["tenant.name"] != "real-tenant" {
		t.Fatalf("expected tenant.name=real-tenant, got %q", attrs["tenant.name"])
	}
	if attrs["service.name"] != "myapp" {
		t.Fatalf("service.name should be preserved, got %q", attrs["service.name"])
	}
	if _, exists := attrs["service.namespace"]; exists {
		t.Fatal("service.namespace should be removed")
	}
	if len(rs.ScopeSpans[0].Spans) != 1 {
		t.Fatal("spans should be preserved")
	}
	if string(rs.ScopeSpans[0].Spans[0].Attributes[0].Key) != "http.method" {
		t.Fatal("span attributes should be preserved")
	}
}

func TestStampTenantIdentityJSONTraces(t *testing.T) {
	req := makeTraceRequest(stringAttr("tenant.id", "victim"))
	rawBody, err := protojson.Marshal(req)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}

	stampedBody, err := stampTenantIdentity(rawBody, "application/json", "", "traces", "42", "real-tenant")
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}

	var result tracecollector.ExportTraceServiceRequest
	opts := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := opts.Unmarshal(stampedBody, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	attrs := make(map[string]string)
	for _, kv := range result.ResourceSpans[0].Resource.Attributes {
		attrs[kv.Key] = kv.Value.GetStringValue()
	}
	if attrs["tenant.id"] != "42" {
		t.Fatalf("expected tenant.id=42, got %q", attrs["tenant.id"])
	}
	if attrs["tenant.name"] != "real-tenant" {
		t.Fatalf("expected tenant.name=real-tenant, got %q", attrs["tenant.name"])
	}
}

func TestStampTenantIdentityProtoMetrics(t *testing.T) {
	req := &metricscollector.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricsv1.ResourceMetrics{{
			Resource: &resourcev1.Resource{Attributes: []*commonv1.KeyValue{stringAttr("service.name", "metric-app")}},
		}},
	}
	rawBody, _ := proto.Marshal(req)

	stampedBody, err := stampTenantIdentity(rawBody, "application/x-protobuf", "", "metrics", "7", "metric-tenant")
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}

	var result metricscollector.ExportMetricsServiceRequest
	if err := proto.Unmarshal(stampedBody, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	attrs := result.ResourceMetrics[0].Resource.Attributes
	found := false
	for _, kv := range attrs {
		if kv.Key == "tenant.id" && kv.Value.GetStringValue() == "7" {
			found = true
		}
	}
	if !found {
		t.Fatal("tenant.id=7 missing from metric resource")
	}
}

func TestStampTenantIdentityProtoLogs(t *testing.T) {
	req := &logscollector.ExportLogsServiceRequest{
		ResourceLogs: []*logsv1.ResourceLogs{{
			Resource: &resourcev1.Resource{Attributes: []*commonv1.KeyValue{stringAttr("service.name", "log-app")}},
		}},
	}
	rawBody, _ := proto.Marshal(req)

	stampedBody, err := stampTenantIdentity(rawBody, "application/x-protobuf", "", "logs", "3", "log-tenant")
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}

	var result logscollector.ExportLogsServiceRequest
	if err := proto.Unmarshal(stampedBody, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	attrs := result.ResourceLogs[0].Resource.Attributes
	found := false
	for _, kv := range attrs {
		if kv.Key == "tenant.name" && kv.Value.GetStringValue() == "log-tenant" {
			found = true
		}
	}
	if !found {
		t.Fatal("tenant.name missing from log resource")
	}
}

func TestStampTenantIdentityGzipRoundTrip(t *testing.T) {
	req := makeTraceRequest(stringAttr("service.name", "gzip-app"))
	rawBody, _ := proto.Marshal(req)

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(rawBody)
	gw.Close()
	gzipBody := buf.Bytes()

	stampedBody, err := stampTenantIdentity(gzipBody, "application/x-protobuf", "gzip", "traces", "99", "gzip-tenant")
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(stampedBody))
	if err != nil {
		t.Fatalf("result is not valid gzip: %v", err)
	}
	defer gr.Close()
	decompressed, _ := io.ReadAll(gr)

	var result tracecollector.ExportTraceServiceRequest
	if err := proto.Unmarshal(decompressed, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	found := false
	for _, kv := range result.ResourceSpans[0].Resource.Attributes {
		if kv.Key == "tenant.id" && kv.Value.GetStringValue() == "99" {
			found = true
		}
	}
	if !found {
		t.Fatal("tenant.id=99 not found in gzip round-tripped output")
	}
}

func TestStampTenantIdentityNoResource(t *testing.T) {
	// ResourceSpans with Resource = nil → new Resource created, no panic
	req := &tracecollector.ExportTraceServiceRequest{
		ResourceSpans: []*tracev1.ResourceSpans{{}}, // Resource is nil
	}
	rawBody, _ := proto.Marshal(req)

	stampedBody, err := stampTenantIdentity(rawBody, "application/x-protobuf", "", "traces", "1", "nil-tenant")
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}

	var result tracecollector.ExportTraceServiceRequest
	if err := proto.Unmarshal(stampedBody, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.ResourceSpans[0].Resource == nil {
		t.Fatal("expected resource to be created")
	}
	found := false
	for _, kv := range result.ResourceSpans[0].Resource.Attributes {
		if kv.Key == "tenant.id" && kv.Value.GetStringValue() == "1" {
			found = true
		}
	}
	if !found {
		t.Fatal("tenant.id missing on newly created resource")
	}
}

func TestStampTenantIdentityMalformedProto(t *testing.T) {
	garbage := []byte("this is not valid protobuf at all !!@@##")
	_, err := stampTenantIdentity(garbage, "application/x-protobuf", "", "traces", "42", "test")
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
	if !isMalformedBody(err) {
		t.Fatalf("expected isMalformedBody=true, got false; err=%v", err)
	}
}

func TestStampTenantIdentityMalformedJSON(t *testing.T) {
	garbage := []byte("{not valid json")
	_, err := stampTenantIdentity(garbage, "application/json", "", "traces", "42", "test")
	if err == nil {
		t.Fatal("expected error for garbage JSON")
	}
	if !isMalformedBody(err) {
		t.Fatalf("expected isMalformedBody=true, got false; err=%v", err)
	}
}

func TestStampTenantIdentityMalformedGzip(t *testing.T) {
	_, err := stampTenantIdentity([]byte("not-gzip-data"), "application/x-protobuf", "gzip", "traces", "42", "test")
	if err == nil {
		t.Fatal("expected error for non-gzip data with gzip encoding")
	}
	if !isMalformedBody(err) {
		t.Fatalf("expected isMalformedBody=true, got false; err=%v", err)
	}
}

func TestIsJSONContentType(t *testing.T) {
	tests := []struct {
		ct       string
		expected bool
	}{
		{"application/x-protobuf", false},
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"Application/JSON", true},
		{"application/json; charset=utf-8; boundary=something", true},
		{"", false},
	}
	for _, tc := range tests {
		got := isJSONContentType(tc.ct)
		if got != tc.expected {
			t.Errorf("isJSONContentType(%q) = %v, want %v", tc.ct, got, tc.expected)
		}
	}
}
