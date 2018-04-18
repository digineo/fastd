package fastd

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

// Records is an array of all possible records for a handshake packet
type Records [RecordMax][]byte

// String returns a textual representation of the records
func (r Records) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("Records[ ")
	for key, val := range r {
		if len(val) == 0 {
			continue
		}
		buffer.WriteString(TLVKey(key).String())
		buffer.WriteRune('=')

		switch TLVKey(key) {
		case RecordProtocolName,
			RecordMethodName,
			RecordVersionName,
			RecordHostname,
			RecordVars:
			buffer.WriteString(string(val))

		case RecordMTU,
			RecordIPv4PrefixLen,
			RecordIPv6PrefixLen:
			fmt.Fprintf(&buffer, "%d", val)

		case RecordIPv4Addr,
			RecordIPv4DstAddr,
			RecordIPv6Addr,
			RecordIPv6DstAddr:
			buffer.WriteString(net.IP(val).String())

		case RecordMethodList:
			fmt.Fprintf(&buffer, "%v", strings.Split(string(val), "\x00"))

		default:
			fmt.Fprintf(&buffer, "%x", val)
		}
		buffer.WriteRune(' ')
	}
	buffer.WriteRune(']')

	return buffer.String()
}
