package fastd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// TLVKey identifies the Type-Length-Value.
type TLVKey uint16

func (key TLVKey) String() string {
	switch key {
	case RecordHandshakeType:
		return "handshake_type"
	case RecordReplyCode:
		return "reply_code"
	case RecordErrorDetail:
		return "error_detail"
	case RecordFlags:
		return "flags"
	case RecordMode:
		return "mode"
	case RecordProtocolName:
		return "protocol_name"
	case RecordSenderKey:
		return "sender_key"
	case RecordRecipientKey:
		return "recipient_key"
	case RecordSenderHandshakeKey:
		return "sender_handshake_key"
	case RecordRecipientHandshakeKey:
		return "recipient_handshake_key"
	case RecordAuthenticationTag:
		return "authentication_tag"
	case RecordMTU:
		return "mtu"
	case RecordMethodName:
		return "method_name"
	case RecordVersionName:
		return "version_name"
	case RecordMethodList:
		return "method_list"
	case RecordTLVMAC:
		return "tlv_mac"
	case RecordIPv4Addr:
		return "ipv4_addr"
	case RecordIPv4DstAddr:
		return "ipv4_dstaddr"
	case RecordIPv4PrefixLen:
		return "ipv4_prefixlen"
	case RecordIPv6Addr:
		return "ipv6_addr"
	case RecordIPv6DstAddr:
		return "ipv6_dstaddr"
	case RecordIPv6PrefixLen:
		return "ipv6_prefixlen"
	case RecordVars:
		return "vars"
	case RecordHostname:
		return "hostname"
	}
	return fmt.Sprintf("%%!(TLVKey value=%02x)", uint16(key))
}

// Known record fields. Fields > RecordTLVMAC are inofficial as of yet.
const (
	RecordHandshakeType TLVKey = iota
	RecordReplyCode
	RecordErrorDetail
	RecordFlags
	RecordMode
	RecordProtocolName
	RecordSenderKey
	RecordRecipientKey
	RecordSenderHandshakeKey
	RecordRecipientHandshakeKey
	RecordAuthenticationTag
	RecordMTU
	RecordMethodName
	RecordVersionName
	RecordMethodList
	RecordTLVMAC

	RecordIPv4Addr
	RecordIPv4DstAddr
	RecordIPv4PrefixLen
	RecordIPv6Addr
	RecordIPv6DstAddr
	RecordIPv6PrefixLen
	RecordVars
	RecordHostname

	RecordMax // RecordMax is not a field, only a const name for the number of known fields.
)

// Records is an array of all possible records for a handshake packet
type Records [RecordMax][]byte

type errValueMissing struct {
	key TLVKey
}

func (err errValueMissing) Error() string {
	return fmt.Sprintf("missing value for %s", err.key.String())
}

// MissingValue reports whether the given error is a missing value, and
// if so, returns the corresponding TLV key as well.
func MissingValue(err error) (TLVKey, bool) {
	switch err.(type) {
	case errValueMissing:
		return err.(errValueMissing).key, true
	case *errValueMissing:
		return err.(*errValueMissing).key, true
	}
	return 0, false
}

// SetHandshakeType updates the RecordHandshakeType field. It returns itself for chaining.
func (r *Records) SetHandshakeType(val HandshakeType) *Records {
	r[RecordHandshakeType] = []byte{byte(val)}
	return r
}

// HandshakeType returns the RecordHandshakeType.
func (r *Records) HandshakeType() (HandshakeType, error) {
	if val := r[RecordHandshakeType]; len(val) == 1 {
		return HandshakeType(val[0]), nil
	}
	return 0, &errValueMissing{RecordHandshakeType}
}

// SetReplyCode updates the RecordReplyCode field. It returns itself for chaining.
func (r *Records) SetReplyCode(val ReplyCode) *Records {
	r[RecordReplyCode] = []byte{byte(val)}
	return r
}

// ReplyCode returns the RecordReplyCode.
func (r *Records) ReplyCode() (ReplyCode, error) {
	if val := r[RecordReplyCode]; len(val) == 1 {
		return ReplyCode(val[0]), nil
	}
	return 0, &errValueMissing{RecordReplyCode}
}

// SetErrorDetail updates the RecordErrorDetail field. It returns itself for chaining.
func (r *Records) SetErrorDetail(key TLVKey) *Records {
	value := make([]byte, 2)
	binary.LittleEndian.PutUint16(value, uint16(key))
	r[RecordErrorDetail] = value
	return r
}

// ErrorDetail returns the RecordErrorDetail.
func (r *Records) ErrorDetail() (TLVKey, error) {
	if val := r[RecordErrorDetail]; len(val) == 2 {
		return TLVKey(binary.LittleEndian.Uint16(val)), nil
	}
	return 0, &errValueMissing{RecordErrorDetail}
}

// SetFlags updates the RecordFlags field. It returns itself for chaining.
func (r *Records) SetFlags(val []byte) *Records {
	r[RecordFlags] = val
	return r
}

// Flags returns the RecordFlags.
func (r *Records) Flags() ([]byte, error) {
	if val := r[RecordFlags]; len(val) > 0 {
		return val, nil
	}
	return nil, &errValueMissing{RecordFlags}
}

// SetMode updates the RecordMode field. It returns itself for chaining.
func (r *Records) SetMode(val Mode) *Records {
	r[RecordMode] = []byte{byte(val)}
	return r
}

// Mode returns the RecordMode.
func (r *Records) Mode() (Mode, error) {
	if val := r[RecordMode]; len(val) == 1 {
		return Mode(val[0]), nil
	}
	return 0, &errValueMissing{RecordMode}
}

// SetProtocolName updates the RecordProtocolName field. It returns itself for chaining.
func (r *Records) SetProtocolName(val string) *Records {
	r[RecordProtocolName] = []byte(val)
	return r
}

// ProtocolName returns the RecordProtocolName.
func (r *Records) ProtocolName() (string, error) {
	return string(r[RecordProtocolName]), nil
}

// SetSenderKey updates the RecordSenderKey field. It returns itself for chaining.
func (r *Records) SetSenderKey(val []byte) *Records {
	r[RecordSenderKey] = val
	return r
}

// SenderKey returns the RecordSenderKey.
func (r *Records) SenderKey() ([]byte, error) {
	return r[RecordSenderKey], nil
}

// SetRecipientKey updates the RecordRecipientKey field. It returns itself for chaining.
func (r *Records) SetRecipientKey(val []byte) *Records {
	r[RecordRecipientKey] = val
	return r
}

// RecipientKey returns the RecordRecipientKey.
func (r *Records) RecipientKey() ([]byte, error) {
	return r[RecordRecipientKey], nil
}

// SetSenderHandshakeKey updates the RecordSenderHandshakeKey field. It returns itself for chaining.
func (r *Records) SetSenderHandshakeKey(val []byte) *Records {
	r[RecordSenderHandshakeKey] = val
	return r
}

// SenderHandshakeKey returns the RecordSenderHandshakeKey.
func (r *Records) SenderHandshakeKey() ([]byte, error) {
	return r[RecordSenderHandshakeKey], nil
}

// SetRecipientHandshakeKey updates the RecordRecipientHandshakeKey field. It returns itself for chaining.
func (r *Records) SetRecipientHandshakeKey(val []byte) *Records {
	r[RecordRecipientHandshakeKey] = val
	return r
}

// RecipientHandshakeKey returns the RecordRecipientHandshakeKey.
func (r *Records) RecipientHandshakeKey() ([]byte, error) {
	return r[RecordRecipientHandshakeKey], nil
}

// SetAuthenticationTag updates the RecordAuthenticationTag field. It returns itself for chaining.
func (r *Records) SetAuthenticationTag(val []byte) *Records {
	r[RecordAuthenticationTag] = val
	return r
}

// AuthenticationTag returns the RecordAuthenticationTag.
func (r *Records) AuthenticationTag() ([]byte, error) {
	return r[RecordAuthenticationTag], nil
}

// SetMTU updates the RecordMTU field. It returns itself for chaining.
func (r *Records) SetMTU(val uint16) *Records {
	binary.LittleEndian.PutUint16(r[RecordMTU], val)
	return r
}

// MTU returns the RecordMTU.
func (r *Records) MTU() (uint16, error) {
	if val := r[RecordMTU]; len(val) == 2 {
		return binary.LittleEndian.Uint16(val), nil
	}
	return 0, &errValueMissing{RecordMTU}
}

// SetMethodName updates the RecordMethodName field. It returns itself for chaining.
func (r *Records) SetMethodName(val string) *Records {
	r[RecordMethodName] = []byte(val)
	return r
}

// MethodName returns the RecordMethodName.
func (r *Records) MethodName() (string, error) {
	return string(r[RecordMethodName]), nil
}

// SetVersionName updates the RecordVersionName field. It returns itself for chaining.
func (r *Records) SetVersionName(val string) *Records {
	r[RecordVersionName] = []byte(val)
	return r
}

// VersionName returns the RecordVersionName.
func (r *Records) VersionName() (string, error) {
	return string(r[RecordVersionName]), nil
}

// SetMethodList updates the RecordMethodList field. It returns itself for chaining.
func (r *Records) SetMethodList(val ...string) *Records {
	var buf bytes.Buffer
	for i, method := range val {
		if i > 0 {
			buf.WriteByte(0x00)
		}
		buf.WriteString(method)
	}
	r[RecordMethodList] = buf.Bytes()
	return r
}

// MethodList returns the RecordMethodList.
func (r *Records) MethodList() (val []string, err error) {
	for _, method := range bytes.Split(r[RecordMethodList], []byte{0x00}) {
		val = append(val, string(method))
	}
	return
}

// SetTLVMAC updates the RecordTLVMAC field. It returns itself for chaining.
func (r *Records) SetTLVMAC(val []byte) *Records {
	r[RecordTLVMAC] = val
	return r
}

// TLVMAC returns the RecordTLVMAC.
func (r *Records) TLVMAC() ([]byte, error) {
	return r[RecordTLVMAC], nil
}

// SetIPv4Addr updates the RecordIPv4Addr field. It returns itself for chaining.
func (r *Records) SetIPv4Addr(ip net.IP) *Records {
	r[RecordIPv4Addr] = []byte(ip.To4())
	return r
}

// IPv4Addr returns the RecordIPv4Addr.
func (r *Records) IPv4Addr() (net.IP, error) {
	if val := r[RecordIPv4Addr]; len(val) == 4 {
		return net.IP(val), nil
	}
	return nil, &errValueMissing{RecordIPv4Addr}
}

// SetIPv4DstAddr updates the RecordIPv4DstAddr field. It returns itself for chaining.
func (r *Records) SetIPv4DstAddr(ip net.IP) *Records {
	r[RecordIPv4DstAddr] = []byte(ip.To4())
	return r
}

// IPv4DstAddr returns the RecordIPv4DstAddr.
func (r *Records) IPv4DstAddr() (net.IP, error) {
	if val := r[RecordIPv4DstAddr]; len(val) == 4 {
		return net.IP(val), nil
	}
	return nil, &errValueMissing{RecordIPv4DstAddr}
}

// SetIPv4PrefixLen updates the RecordIPv4PrefixLen field. It returns itself for chaining.
func (r *Records) SetIPv4PrefixLen(val []byte) *Records {
	r[RecordIPv4PrefixLen] = val
	return r
}

// IPv4PrefixLen returns the RecordIPv4PrefixLen.
func (r *Records) IPv4PrefixLen() ([]byte, error) {
	return r[RecordIPv4PrefixLen], nil
}

// SetIPv6Addr updates the RecordIPv6Addr field. It returns itself for chaining.
func (r *Records) SetIPv6Addr(ip net.IP) *Records {
	r[RecordIPv6Addr] = []byte(ip.To16())
	return r
}

// IPv6Addr returns the RecordIPv6Addr.
func (r *Records) IPv6Addr() (net.IP, error) {
	if val := r[RecordIPv6Addr]; len(val) == 16 {
		return net.IP(val), nil
	}
	return nil, &errValueMissing{RecordIPv6Addr}
}

// SetIPv6DstAddr updates the RecordIPv6DstAddr field. It returns itself for chaining.
func (r *Records) SetIPv6DstAddr(ip net.IP) *Records {
	r[RecordIPv6DstAddr] = []byte(ip.To16())
	return r
}

// IPv6DstAddr returns the RecordIPv6DstAddr.
func (r *Records) IPv6DstAddr() (net.IP, error) {
	if val := r[RecordIPv6DstAddr]; len(val) == 16 {
		return net.IP(val), nil
	}
	return nil, &errValueMissing{RecordIPv6DstAddr}
}

// SetIPv6PrefixLen updates the RecordIPv6PrefixLen field. It returns itself for chaining.
func (r *Records) SetIPv6PrefixLen(val []byte) *Records {
	r[RecordIPv6PrefixLen] = val
	return r
}

// IPv6PrefixLen returns the RecordIPv6PrefixLen.
func (r *Records) IPv6PrefixLen() ([]byte, error) {
	return r[RecordIPv6PrefixLen], nil
}

// SetVars updates the RecordVars field. It returns itself for chaining.
func (r *Records) SetVars(val []byte) *Records {
	r[RecordVars] = val
	return r
}

// Vars returns the RecordVars.
func (r *Records) Vars() ([]byte, error) {
	return r[RecordVars], nil
}

// SetHostname updates the RecordHostname field. It returns itself for chaining.
func (r *Records) SetHostname(val string) *Records {
	r[RecordHostname] = []byte(val)
	return r
}

// Hostname returns the RecordHostname.
func (r *Records) Hostname() (string, error) {
	return string(r[RecordHostname]), nil
}

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
