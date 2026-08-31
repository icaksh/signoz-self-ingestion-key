package ingest

import (
	"testing"

	"google.golang.org/protobuf/proto"

	tracecollector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

func benchTraceRequest() *tracecollector.ExportTraceServiceRequest {
	var spans []*tracev1.ResourceSpans
	for i := 0; i < 50; i++ {
		spans = append(spans, &tracev1.ResourceSpans{
			Resource: &resourcev1.Resource{
				Attributes: []*commonv1.KeyValue{
					strKV("service.name", "bench-service"),
					strKV("service.namespace", "client-claimed"),
					strKV("tenant.id", "attacker"),
				},
			},
		})
	}
	return &tracecollector.ExportTraceServiceRequest{ResourceSpans: spans}
}

func BenchmarkStampProtobuf(b *testing.B) {
	raw, _ := proto.Marshal(benchTraceRequest())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := stampTenantIdentity(raw, "application/x-protobuf", "", "traces", "42", "acme"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStampJSON(b *testing.B) {
	raw, _ := protojsonMarshal(benchTraceRequest())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := stampTenantIdentity(raw, "application/json", "", "traces", "42", "acme"); err != nil {
			b.Fatal(err)
		}
	}
}
