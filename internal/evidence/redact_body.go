package evidence

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
)

// redactBody sanitizes a request/response body according to its
// content type -- task section 9. JSON is parsed and redacted
// recursively (so a secret nested inside an object or array is caught,
// not just top-level fields); form-urlencoded is parsed as key=value
// pairs; anything else (multipart/form-data, an unrecognized type, or
// content that fails to parse as its declared type) falls back to
// redactText's generic pattern match -- "support common content types
// WHERE PRACTICAL," never a hard requirement to fully parse every
// possible body shape. Unrelated content is never destroyed: only
// values under a matching key are ever replaced.
func redactBody(contentType, body string) string {
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "application/json"):
		if redacted, ok := redactJSON(body); ok {
			return redacted
		}
		return redactText(body) // malformed JSON -- fall back rather than fail
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		if redacted, ok := redactForm(body); ok {
			return redacted
		}
		return redactText(body)
	case strings.Contains(ct, "multipart/"):
		if redacted, ok := redactMultipart(contentType, body); ok {
			return redacted
		}
		return redactText(body)
	default:
		return redactText(body)
	}
}

// redactMultipart parses body as a MIME multipart message (using its
// declared boundary from contentType) and replaces the VALUE of every
// part whose form field name matches sensitiveFieldNames, reassembling
// the message with the SAME boundary -- task section 9's "support
// common content types where practical," extended to multipart/
// form-data specifically because its field-name/value pairing (a
// Content-Disposition header naming the field, with the value on
// following lines) doesn't fit the generic key=value TEXT pattern
// redactText/redactForm/redactJSON all share; only a real multipart
// parse can find it. A file part's CONTENT is never rewritten (only a
// literal field value can match a sensitive name here), consistent
// with "do not destroy unrelated evidence." Returns ok=false if the
// boundary is missing or the body isn't valid multipart at all, so the
// caller falls back to the generic text pattern instead of losing the
// evidence entirely.
func redactMultipart(contentType, body string) (string, bool) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", false
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "", false
	}

	reader := multipart.NewReader(strings.NewReader(body), boundary)
	var out bytes.Buffer
	writer := multipart.NewWriter(&out)
	if err := writer.SetBoundary(boundary); err != nil {
		return "", false
	}

	sawAnyPart := false
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false
		}
		sawAnyPart = true

		value, readErr := io.ReadAll(part)
		if readErr != nil {
			return "", false
		}

		fieldWriter, err := writer.CreatePart(part.Header)
		if err != nil {
			return "", false
		}
		if isSensitiveFieldName(part.FormName()) {
			fieldWriter.Write([]byte(redactedPlaceholder))
		} else {
			fieldWriter.Write(value)
		}
	}
	writer.Close()

	if !sawAnyPart {
		return "", false
	}
	return out.String(), true
}

// redactJSON unmarshals body, redacts every value whose key matches
// sensitiveFieldNames at ANY nesting depth (objects and arrays), and
// re-marshals it. Returns ok=false if body isn't valid JSON at all, so
// the caller can fall back to the generic text pattern instead of
// discarding the evidence entirely.
func redactJSON(body string) (string, bool) {
	var v interface{}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return "", false
	}
	redacted := redactJSONValue(v)
	out, err := json.Marshal(redacted)
	if err != nil {
		return "", false
	}
	return string(out), true
}

func redactJSONValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, child := range val {
			if isSensitiveFieldName(k) {
				out[k] = redactedPlaceholder
				continue
			}
			out[k] = redactJSONValue(child)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, child := range val {
			out[i] = redactJSONValue(child)
		}
		return out
	default:
		return val
	}
}

// redactForm parses body as application/x-www-form-urlencoded and
// redacts the value of every field whose name matches
// sensitiveFieldNames. Returns ok=false only if url.ParseQuery itself
// errors (rare -- form values are already permissive), so the caller
// can fall back to the generic text pattern.
func redactForm(body string) (string, bool) {
	values, err := url.ParseQuery(body)
	if err != nil {
		return "", false
	}
	for key := range values {
		if isSensitiveFieldName(key) {
			values.Set(key, redactedPlaceholder)
		}
	}
	return values.Encode(), true
}
