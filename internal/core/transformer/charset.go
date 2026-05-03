package transformer

type Charset uint8

const (
	CharsetAlphanumeric Charset = iota
	CharsetHex
	CharsetBase64URL
	CharsetAlphaUpper
	CharsetBase64
)

var (
	csAlphanumeric = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	csHex          = []byte("0123456789abcdef")
	csBase64URL    = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
	csAlphaUpper   = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	csBase64       = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
)

func (c Charset) Bytes() []byte {
	switch c {
	case CharsetHex:
		return csHex
	case CharsetBase64URL:
		return csBase64URL
	case CharsetAlphaUpper:
		return csAlphaUpper
	case CharsetBase64:
		return csBase64
	default:
		return csAlphanumeric
	}
}

func ParseCharset(s string) (Charset, bool) {
	switch s {
	case "alphanumeric":
		return CharsetAlphanumeric, true
	case "hex":
		return CharsetHex, true
	case "base64url":
		return CharsetBase64URL, true
	case "alphaupper":
		return CharsetAlphaUpper, true
	case "base64":
		return CharsetBase64, true
	default:
		return 0, false
	}
}
