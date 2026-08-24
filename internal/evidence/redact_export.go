package evidence

// RedactedPlaceholder is the exact string every redacted value in this
// codebase is replaced with -- exported so other packages that need to
// recognize or reproduce a redacted value (e.g. internal/parameters,
// deciding whether to persist a discovered input's observed value) use
// the SAME literal rather than inventing their own.
const RedactedPlaceholder = redactedPlaceholder

// IsSensitiveFieldName reports whether name (a form field, JSON key,
// query parameter, or similar) is one of this package's own
// established sensitive-field names (password, token, secret, ...) --
// exported so other packages that discover named application inputs
// (internal/parameters) can decide whether to redact a value BEFORE
// ever persisting/logging it, reusing this package's own blocklist
// rather than maintaining a second, potentially-drifting one. See
// redact.go's sensitiveFieldNames for the exact list.
func IsSensitiveFieldName(name string) bool {
	return isSensitiveFieldName(name)
}
