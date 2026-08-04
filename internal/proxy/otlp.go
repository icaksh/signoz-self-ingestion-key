package proxy

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	logscollector "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	metricscollector "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	tracecollector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
)

// stampTenantIdentity reads raw OTLP body bytes, stamps tenant identity onto
// every resource, and returns the re-encoded body in the same format. If
// contentEncoding is "gzip", input is decompressed first and output is
// re-compressed.
func stampTenantIdentity(rawBody []byte, contentType, contentEncoding, signalType string, tenantID, tenantName string) ([]byte, error) {
	payload := rawBody
	wasGzip := strings.EqualFold(contentEncoding, "gzip")
	if wasGzip {
		var err error
		payload, err = decompressGzip(rawBody)
		if err != nil {
			return nil, fmt.Errorf("gzip decompress: %w", err)
		}
	}

	isJSON := isJSONContentType(contentType)

	msg, err := unmarshalOTLP(payload, isJSON, signalType)
	if err != nil {
		return nil, fmt.Errorf("otlp unmarshal: %w", err)
	}

	stampResources(msg, tenantID, tenantName)

	var encoded []byte
	if isJSON {
		encoded, err = protojson.Marshal(msg)
	} else {
		encoded, err = proto.Marshal(msg)
	}
	if err != nil {
		return nil, fmt.Errorf("otlp marshal: %w", err)
	}

	if wasGzip {
		encoded, err = compressGzip(encoded)
		if err != nil {
			return nil, fmt.Errorf("gzip compress: %w", err)
		}
	}

	return encoded, nil
}

// isJSONContentType returns true if the Content-Type indicates JSON.
// Accepts "application/json" and variants with charset or parameters.
func isJSONContentType(ct string) bool {
	mediaType, _, _ := strings.Cut(ct, ";")
	mediaType = strings.TrimSpace(mediaType)
	return strings.EqualFold(mediaType, "application/json")
}

// unmarshalOTLP parses payload into the appropriate OTLP request type.
func unmarshalOTLP(payload []byte, isJSON bool, signalType string) (proto.Message, error) {
	var msg proto.Message
	switch signalType {
	case "traces":
		msg = &tracecollector.ExportTraceServiceRequest{}
	case "metrics":
		msg = &metricscollector.ExportMetricsServiceRequest{}
	case "logs":
		msg = &logscollector.ExportLogsServiceRequest{}
	default:
		return nil, fmt.Errorf("unknown signal type: %s", signalType)
	}

	var err error
	if isJSON {
		opts := protojson.UnmarshalOptions{DiscardUnknown: true}
		err = opts.Unmarshal(payload, msg)
	} else {
		err = proto.Unmarshal(payload, msg)
	}
	return msg, err
}

// stampResources iterates all resource carriers in the message and stamps
// tenant identity onto each resource.
func stampResources(msg proto.Message, tenantID, tenantName string) {
	switch m := msg.(type) {
	case *tracecollector.ExportTraceServiceRequest:
		for _, rs := range m.ResourceSpans {
			stampSingleResource(&rs.Resource, tenantID, tenantName)
		}
	case *metricscollector.ExportMetricsServiceRequest:
		for _, rm := range m.ResourceMetrics {
			stampSingleResource(&rm.Resource, tenantID, tenantName)
		}
	case *logscollector.ExportLogsServiceRequest:
		for _, rl := range m.ResourceLogs {
			stampSingleResource(&rl.Resource, tenantID, tenantName)
		}
	}
}

// stampSingleResource filters existing tenant/service attributes and inserts
// server-side tenant.id and tenant.name. If res points to nil, it allocates
// a new Resource.
func stampSingleResource(res **resourcev1.Resource, tenantID, tenantName string) {
	if *res == nil {
		*res = &resourcev1.Resource{}
	}

	// Filter out client-claimed tenant attributes and service.namespace
	filtered := make([]*commonv1.KeyValue, 0, len((*res).Attributes)+2)
	for _, kv := range (*res).Attributes {
		if kv.Key == "tenant.id" || kv.Key == "tenant.name" || kv.Key == "service.namespace" {
			continue
		}
		filtered = append(filtered, kv)
	}

	filtered = append(filtered,
		&commonv1.KeyValue{
			Key:   "tenant.id",
			Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: tenantID}},
		},
		&commonv1.KeyValue{
			Key:   "tenant.name",
			Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: tenantName}},
		},
	)

	(*res).Attributes = filtered
}

// decompressGzip decompresses a gzip-compressed payload.
func decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// compressGzip compresses a payload with gzip.
func compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// isMalformedBody returns true if the error indicates a malformed request
// body (proto/JSON decode failure, bad gzip) rather than a transient or
// server-side error.
func isMalformedBody(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return errors.Is(err, io.ErrUnexpectedEOF) ||
		strings.Contains(msg, "cannot parse") ||
		strings.Contains(msg, "syntax error") ||
		strings.Contains(msg, "unknown field") ||
		strings.Contains(msg, "invalid header") ||
		strings.Contains(msg, "unexpected EOF")
}
