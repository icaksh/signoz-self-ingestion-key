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
// Existing tenant SD-IDs are stripped; all other SD-IDs are preserved.
// Malformed or too-short messages are returned unchanged (best effort).
func StampSyslogMessage(rawMsg []byte, tenantID int64) []byte {
	if len(rawMsg) == 0 || rawMsg[0] != '<' {
		return rawMsg
	}

	// Find the PRI (ends at the first '>')
	priEnd := strings.IndexByte(string(rawMsg), '>')
	if priEnd == -1 {
		return rawMsg
	}

	// After PRI: VERSION SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD [SP MSG]
	afterPRI := strings.TrimLeft(string(rawMsg[priEnd+1:]), " ")
	parts := strings.SplitN(afterPRI, " ", 7)
	if len(parts) < 6 {
		return rawMsg // too short to be a valid RFC 5424 message
	}

	headerFields := parts[:6] // VERSION through MSGID (fields[5] is SD start)
	sdSection := parts[5]
	if len(parts) > 6 {
		// The 7th part is the remainder after the first space in the SD section
		sdSection = parts[5] + " " + parts[6]
	}

	sdBlocks, msg := parseSDAndMsg(sdSection)

	filtered := make([]string, 0, len(sdBlocks)+1)
	for _, block := range sdBlocks {
		if !isTenantSDID(block) {
			filtered = append(filtered, block)
		}
	}

	tenantBlock := fmt.Sprintf(`[tenant@%d tenant-id="%d"]`, tenantID, tenantID)
	filtered = append(filtered, tenantBlock)

	var newSD string
	if len(filtered) == 0 {
		newSD = "-"
	} else {
		newSD = strings.Join(filtered, "")
	}

	var b strings.Builder
	b.Write(rawMsg[:priEnd+1])     // <PRI>
	b.WriteString(headerFields[0]) // VERSION follows PRI directly
	for i := 1; i < 5; i++ {
		b.WriteByte(' ')
		b.WriteString(headerFields[i])
	}
	b.WriteByte(' ')
	b.WriteString(newSD)
	if msg != "" {
		b.WriteByte(' ')
		b.WriteString(msg)
	}

	return []byte(b.String())
}

// parseSDAndMsg splits the structured-data section into SD blocks ([...])
// and the trailing MSG.
func parseSDAndMsg(section string) (sdBlocks []string, msg string) {
	if section == "-" {
		return nil, ""
	}
	if strings.HasPrefix(section, "- ") {
		// Nil SD marker followed by MSG
		return nil, strings.TrimLeft(section[2:], " ")
	}

	i := 0
	for i < len(section) {
		switch {
		case section[i] == '[':
			end := strings.IndexByte(section[i:], ']')
			if end == -1 {
				// Malformed — treat remainder as msg
				return sdBlocks, section[i:]
			}
			sdBlocks = append(sdBlocks, section[i:i+end+1])
			i += end + 1
		case section[i] == ' ':
			msg = strings.TrimLeft(section[i:], " ")
			return sdBlocks, msg
		default:
			// Non-SD content before any brackets (shouldn't happen in valid
			// RFC 5424) — treat the remainder as msg.
			return sdBlocks, section[i:]
		}
	}
	return sdBlocks, ""
}

func isTenantSDID(block string) bool {
	return strings.HasPrefix(block, tenantSDIDPrefix)
}
