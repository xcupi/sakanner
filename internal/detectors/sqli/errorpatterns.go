package sqli

import "strings"

// dbErrorPattern is one recognizable database error signature,
// associated with a database family where identifiable. Substrings are
// matched case-insensitively; several candidate phrases per family
// avoid relying on any single exact error string, since real-world
// driver/version/language error text varies. See
// docs/phase-3-3-sqli.md "Database error patterns" for how to extend
// this table -- it exists as data, not scattered regexes/string
// literals throughout detector.go.
type dbErrorPattern struct {
	family     string
	substrings []string
}

// dbErrorPatterns is intentionally ordered with "generic" last: it is
// only ever the fallback when nothing more specific matched (see
// matchDBError), since cross-family wording alone is weaker evidence
// (a non-database error could plausibly use similar phrasing) than a
// phrase distinctive to one real database family.
var dbErrorPatterns = []dbErrorPattern{
	{
		family: "mysql",
		substrings: []string{
			"you have an error in your sql syntax",
			"warning: mysql",
			"mysqli_",
			"mysql_fetch",
			"sqlstate[42000]",
		},
	},
	{
		family: "postgresql",
		substrings: []string{
			"pg_query()",
			"pg_exec()",
			"postgresql query failed",
			"syntax error at or near",
			"org.postgresql.util.psqlexception",
		},
	},
	{
		family: "mssql",
		substrings: []string{
			"unclosed quotation mark",
			"microsoft ole db provider",
			"system.data.sqlclient",
			"incorrect syntax near",
			"microsoft sql server",
		},
	},
	{
		family: "sqlite",
		substrings: []string{
			"sqlite3.operationalerror",
			"sqlite_error",
			"sqlite3.dbapi2.programmingerror",
			`near "`,
		},
	},
	{
		family: "oracle",
		substrings: []string{
			"ora-00933",
			"ora-01756",
			"ora-00936",
			"pls-00103",
			"oracle.jdbc",
		},
	},
	{
		family: "generic",
		substrings: []string{
			"sql syntax",
			"sql error",
			"database error",
			"query failed",
			"syntax error",
		},
	},
}

// matchDBError reports whether body contains a recognizable database
// error signature, and which family matched -- "generic" only if
// nothing family-specific did. An empty/false result means body
// contains no recognized database-error-shaped text at all.
func matchDBError(body string) (family string, matched bool) {
	lower := strings.ToLower(body)
	genericMatched := false
	for _, p := range dbErrorPatterns {
		for _, s := range p.substrings {
			if !strings.Contains(lower, s) {
				continue
			}
			if p.family == "generic" {
				genericMatched = true
				continue
			}
			return p.family, true
		}
	}
	if genericMatched {
		return "generic", true
	}
	return "", false
}
