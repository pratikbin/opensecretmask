package proxy

import (
	"bytes"
	"encoding/json"
)

// opaqueField returns the name of the byte-fragile field carried by an
// Anthropic content block of the given type, or "" if the type has none.
// The API computes these fields over the (masked) content the model produced;
// byte-level masking must leave them identical or the API rejects the request.
func opaqueField(blockType string) string {
	switch blockType {
	case "thinking":
		return "signature"
	case "redacted_thinking":
		return "data"
	default:
		return ""
	}
}

// preserveOpaqueBlocks restores byte-fragile thinking-block fields from
// original into masked. A thinking block's `signature` (and a redacted_thinking
// block's `data`) is a cryptographic blob the API rejects if any byte changes;
// a detection regex can match inside it and corrupt it during masking,
// producing a 400 "Invalid signature in thinking block" on the next turn.
//
// The thinking text itself is left masked on purpose: the signature was
// computed over the masked content the model saw, so MaskBody re-masking that
// text is required for the signature to validate. Only the opaque field is
// restored.
//
// masked is returned unchanged when either body is not a JSON object, the two
// bodies disagree on opaque-block count, or there are no opaque blocks.
// Masking is value-for-value, so opaque blocks keep their document order.
func preserveOpaqueBlocks(original, masked []byte) []byte {
	origDoc, err := decodeJSONObject(original)
	if err != nil {
		return masked
	}
	origBlocks := opaqueBlocks(origDoc)
	if len(origBlocks) == 0 {
		return masked
	}
	maskedDoc, err := decodeJSONObject(masked)
	if err != nil {
		return masked
	}
	maskedBlocks := opaqueBlocks(maskedDoc)
	if len(maskedBlocks) != len(origBlocks) {
		return masked
	}

	restored := false
	for i, mb := range maskedBlocks {
		field := opaqueField(stringValue(mb["type"]))
		if field == "" {
			continue
		}
		if v, ok := origBlocks[i][field]; ok {
			mb[field] = v
			restored = true
		}
	}
	if !restored {
		return masked
	}

	out, err := json.Marshal(maskedDoc)
	if err != nil {
		return masked
	}
	return out
}

// opaqueBlocks returns every messages[].content[] object carrying a
// byte-fragile field, in document order.
func opaqueBlocks(doc map[string]any) []map[string]any {
	messages, ok := doc["messages"].([]any)
	if !ok {
		return nil
	}
	var out []map[string]any
	for _, m := range messages {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		content, ok := msg["content"].([]any)
		if !ok {
			continue
		}
		for _, c := range content {
			block, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if opaqueField(stringValue(block["type"])) != "" {
				out = append(out, block)
			}
		}
	}
	return out
}

// decodeJSONObject decodes b into a JSON object, keeping numbers as
// json.Number so a re-marshal reproduces them exactly.
func decodeJSONObject(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// stringValue returns v as a string, or "" if v is not a string.
func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

