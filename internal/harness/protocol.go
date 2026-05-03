package harness

import (
	"encoding/json"
	"io"

	"github.com/pratikbin/opensecretmask/internal/core/detector"
)

type Direction int

const (
	DirMask Direction = iota
	DirUnmask
	DirObserve
)

func (d Direction) String() string {
	switch d {
	case DirMask:
		return "mask"
	case DirUnmask:
		return "unmask"
	case DirObserve:
		return "observe"
	default:
		return "unknown"
	}
}

type Target struct {
	Path     []string
	Content  string
	Encoding string
	Skip     bool
}

type Request struct {
	Harness   string
	SessionID string
	EventName string
	Direction Direction
	ToolName  string
	Cwd       string
	Targets   []Target
}

type Response struct {
	Modified   bool
	Targets    []Target
	Findings   []detector.Finding
	Notes      []string
	DenyReason string
}

type Adapter interface {
	Name() string
	ParseRequest(stdin io.Reader) (*Request, json.RawMessage, error)
	EmitResponse(w io.Writer, original json.RawMessage, resp *Response) error
	EventDirection(eventName, toolName string) (Direction, error)
}
