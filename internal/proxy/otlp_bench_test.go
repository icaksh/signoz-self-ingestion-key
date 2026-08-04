package proxy

import (
	"crypto/rand"
	"fmt"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	tracecollector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

// make100SpanPayload generates a realistic ExportTraceServiceRequest with
// 1 resource, 1 scope, and 100 spans.
func make100SpanPayload() *tracecollector.ExportTraceServiceRequest {
	spans := make([]*tracev1.Span, 100)
	for i := range 100 {
		tid := make([]byte, 16)
		sid := make([]byte, 8)
		_, _ = rand.Read(tid)
		_, _ = rand.Read(sid)

		spans[i] = &tracev1.Span{
			TraceId:           tid,
			SpanId:            sid,
			Name:              fmt.Sprintf("span-%d", i),
			Kind:              tracev1.Span_SPAN_KIND_SERVER,
			StartTimeUnixNano: uint64(i * 1_000_000),
			EndTimeUnixNano:   uint64(i*1_000_000 + 500_000),
			Attributes: []*commonv1.KeyValue{
				{Key: "http.method", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: "GET"}}},
				{Key: "http.url", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: fmt.Sprintf("/api/items/%d", i)}}},
				{Key: "http.status_code", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_IntValue{IntValue: 200}}},
				{Key: "db.statement", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: "SELECT * FROM items WHERE id = ?"}}},
				{Key: "custom.attr", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: fmt.Sprintf("value-%d", i)}}},
			},
		}
	}

	return &tracecollector.ExportTraceServiceRequest{
		ResourceSpans: []*tracev1.ResourceSpans{{
			Resource: &resourcev1.Resource{
				Attributes: []*commonv1.KeyValue{
					{Key: "service.name", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: "benchmark-service"}}},
					{Key: "service.version", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: "1.0.0"}}},
					{Key: "deployment.environment", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: "production"}}},
					{Key: "host.name", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: "host-01"}}},
					{Key: "tenant.id", Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: "victim"}}},
				},
			},
			ScopeSpans: []*tracev1.ScopeSpans{{
				Spans: spans,
			}},
		}},
	}
}

func BenchmarkStampProtobuf(b *testing.B) {
	req := make100SpanPayload()
	raw, err := proto.Marshal(req)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := stampTenantIdentity(raw, "application/x-protobuf", "", "traces", "42", "bench-tenant")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStampJSON(b *testing.B) {
	req := make100SpanPayload()
	raw, err := protojson.Marshal(req)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := stampTenantIdentity(raw, "application/json", "", "traces", "42", "bench-tenant")
		if err != nil {
			b.Fatal(err)
		}
	}
}
