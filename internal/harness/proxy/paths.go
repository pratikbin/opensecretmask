package proxy

func pathScopedForMask(p string) bool {
	switch p {
	case "/v1/messages", "/v1/messages/count_tokens":
		return true
	default:
		return false
	}
}

func pathScopedForUnmask(p string) bool {
	return p == "/v1/messages"
}
