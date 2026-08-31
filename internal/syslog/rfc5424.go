package syslog

import (
	"fmt"
	"strings"
)

const tenantSDIDPrefix = "[tenant@"

// StampSyslogMessage injects a tenant SD-ID into an RFC 5424 message:
//
//	[tenant@<id> tenant-id="<id>"]
//
// and prefixes the MSG body with "[<id>][<name>] " so tenant identity is
// visible in the body text itself, not just structured data.
//
// Existing tenant SD-IDs are stripped; all other SD-IDs are preserved; the
// header fields (including MSGID) are preserved. Malformed or too-short
// messages are returned unchanged (best effort).
func StampSyslogMessage(rawMsg []byte, tenantID int64, tenantName string) []byte {
	if len(rawMsg) == 0 || rawMsg[0] != '<' {
		return rawMsg
	}

	priEnd := strings.IndexByte(string(rawMsg), '>')
	if priEnd == -1 {
		return rawMsg
	}

	// VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD [SP MSG]
	afterPRI := strings.TrimLeft(string(rawMsg[priEnd+1:]), " ")
	parts := strings.SplitN(afterPRI, " ", 7)
	if len(parts) < 7 {
		return rawMsg // too short to be a valid RFC 5424 message
	}

	header := parts[:6] // VERSION through MSGID
	sdAndMsg := parts[6]

	sdBlocks, msg := parseSDAndMsg(sdAndMsg)

	filtered := make([]string, 0, len(sdBlocks)+1)
	for _, block := range sdBlocks {
		if !isTenantSDID(block) {
			filtered = append(filtered, block)
		}
	}

	tenantBlock := fmt.Sprintf(`[tenant@%d tenant-id="%d"]`, tenantID, tenantID)
	filtered = append(filtered, tenantBlock)

	newSD := "-"
	if len(filtered) > 0 {
		newSD = strings.Join(filtered, "")
	}

	var b strings.Builder
	b.Write(rawMsg[:priEnd+1])
	b.WriteString(header[0])
	for i := 1; i < len(header); i++ {
		b.WriteByte(' ')
		b.WriteString(header[i])
	}
	b.WriteByte(' ')
	b.WriteString(newSD)
	if msg != "" {
		b.WriteByte(' ')
		fmt.Fprintf(&b, "[%d][%s] ", tenantID, tenantName)
		b.WriteString(msg)
	}

	return []byte(b.String())
}

// parseSDAndMsg splits the structured-data section into SD blocks ([...]) and
// the trailing MSG.
func parseSDAndMsg(section string) (sdBlocks []string, msg string) {
	if section == "-" {
		return nil, ""
	}
	if strings.HasPrefix(section, "- ") {
		return nil, strings.TrimLeft(section[2:], " ")
	}

	i := 0
	for i < len(section) {
		switch {
		case section[i] == '[':
			end := strings.IndexByte(section[i:], ']')
			if end == -1 {
				return sdBlocks, section[i:]
			}
			sdBlocks = append(sdBlocks, section[i:i+end+1])
			i += end + 1
		case section[i] == ' ':
			msg = strings.TrimLeft(section[i:], " ")
			return sdBlocks, msg
		default:
			return sdBlocks, section[i:]
		}
	}
	return sdBlocks, ""
}

func isTenantSDID(block string) bool {
	return strings.HasPrefix(block, tenantSDIDPrefix)
}
