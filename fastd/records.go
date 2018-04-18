package fastd

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

// Records is an array of all possible records for a handshake packet
type Records [RECORD_MAX][]byte

// String returns a textual representation of the records
func (r Records) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("Records[ ")
	for key, val := range r {
		if len(val) == 0 {
			continue
		}
		buffer.WriteString(TLV_KEY(key).String())
		buffer.WriteRune('=')

		switch TLV_KEY(key) {
		case RECORD_PROTOCOL_NAME,
			RECORD_METHOD_NAME,
			RECORD_VERSION_NAME,
			RECORD_HOSTNAME,
			RECORD_VARS:
			buffer.WriteString(string(val))

		case RECORD_MTU,
			RECORD_IPV4_PREFIXLEN,
			RECORD_IPV6_PREFIXLEN:
			fmt.Fprintf(&buffer, "%d", val)

		case RECORD_IPV4_ADDR,
			RECORD_IPV4_DSTADDR,
			RECORD_IPV6_ADDR,
			RECORD_IPV6_DSTADDR:
			buffer.WriteString(net.IP(val).String())

		case RECORD_METHOD_LIST:
			fmt.Fprintf(&buffer, "%v", strings.Split(string(val), "\x00"))

		default:
			fmt.Fprintf(&buffer, "%x", val)
		}
		buffer.WriteRune(' ')
	}
	buffer.WriteRune(']')

	return buffer.String()
}
