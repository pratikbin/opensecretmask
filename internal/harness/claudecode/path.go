package claudecode

import (
	"encoding/json"
	"fmt"
)

// extractByPath walks JSON path components into raw and returns string values.
// "*" matches every element of an array.
func extractByPath(raw json.RawMessage, path []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("path: unmarshal: %w", err)
	}
	values := walkExtract(v, path)
	out := make([]string, 0, len(values))
	for _, val := range values {
		switch x := val.(type) {
		case string:
			out = append(out, x)
		case []any:
			// arrays of strings (e.g. Glob.files)
			for _, e := range x {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
		default:
			// non-string leaf — ignore
		}
	}
	return out, nil
}

func walkExtract(v any, path []string) []any {
	if len(path) == 0 {
		return []any{v}
	}
	head, rest := path[0], path[1:]
	if head == "*" {
		arr, ok := v.([]any)
		if !ok {
			return nil
		}
		var out []any
		for _, el := range arr {
			out = append(out, walkExtract(el, rest)...)
		}
		return out
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	child, exists := m[head]
	if !exists {
		return nil
	}
	return walkExtract(child, rest)
}

// replaceByPath returns raw with each leaf at path replaced by the corresponding value.
// values length must equal the number of leaves found at that path.
func replaceByPath(raw json.RawMessage, path []string, values []string) (json.RawMessage, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	idx := 0
	res, _, err := walkReplace(v, path, values, &idx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(res)
}

func walkReplace(v any, path []string, values []string, idx *int) (any, bool, error) {
	if len(path) == 0 {
		switch v.(type) {
		case string:
			if *idx >= len(values) {
				return v, false, fmt.Errorf("replaceByPath: not enough replacement values")
			}
			rep := values[*idx]
			*idx++
			return rep, true, nil
		default:
			return v, false, nil
		}
	}
	head, rest := path[0], path[1:]
	if head == "*" {
		arr, ok := v.([]any)
		if !ok {
			return v, false, nil
		}
		for i, el := range arr {
			rep, ok, err := walkReplace(el, rest, values, idx)
			if err != nil {
				return nil, false, err
			}
			if ok {
				arr[i] = rep
			}
		}
		return arr, true, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return v, false, nil
	}
	child, exists := m[head]
	if !exists {
		return v, false, nil
	}
	rep, ok, err := walkReplace(child, rest, values, idx)
	if err != nil {
		return nil, false, err
	}
	if ok {
		m[head] = rep
	}
	return m, true, nil
}
