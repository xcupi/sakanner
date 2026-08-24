package parameters

import "strings"

// commandParameterFieldNames is an exact-match, case-insensitive list
// of common command/host-reference parameter names -- deliberately
// the SAME set internal/detectors/cmdinjection's own private
// commandLikeParameterNames list already uses (host, hostname, ip,
// address, domain, command, cmd, exec, executable, program, file,
// path, target, query), kept here instead so a future active detector
// never needs to duplicate or import it -- mirroring
// IsLikelySecurityToken/IsLikelyObjectIdentifier/IsLikelyURLParameter's
// own established precedent exactly.
var commandParameterFieldNames = map[string]bool{
	"host": true, "hostname": true, "ip": true, "address": true,
	"domain": true, "command": true, "cmd": true, "exec": true,
	"executable": true, "program": true, "file": true, "path": true,
	"target": true, "query": true,
}

// IsLikelyCommandParameter conservatively reports whether name looks
// like a parameter that reaches command execution/construction --
// name-based only, never derived from a field's discovered VALUE. Used
// by internal/detectors/cmdinjectionactive.Eligible.
//
// A path-location parameter's NAME is never crawl-discovered verbatim
// -- internal/parameters.InferPathInputs (Phase 3.23) derives it from
// the preceding static path segment plus a fixed "_id" (numeric
// values) or "_value" (everything else) suffix (see path.go's own
// pathInputName). So a genuinely command-shaped path segment (e.g.
// "/api/ping/host/{value}") is discovered as "host_value", never bare
// "host" -- this function strips exactly those two known,
// conservative suffixes before the exact-match check, so path-location
// command parameters are recognized without loosening the allowlist
// itself or matching anything InferPathInputs wouldn't itself have
// produced.
func IsLikelyCommandParameter(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if commandParameterFieldNames[n] {
		return true
	}
	for _, suffix := range []string{"_value", "_id"} {
		if base, ok := strings.CutSuffix(n, suffix); ok && commandParameterFieldNames[base] {
			return true
		}
	}
	return false
}
