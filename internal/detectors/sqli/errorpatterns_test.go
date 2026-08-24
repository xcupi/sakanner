package sqli

import "testing"

func TestMatchDBError_MySQL(t *testing.T) {
	family, matched := matchDBError("Warning: mysql_fetch_array() expects parameter 1 to be resource")
	if !matched || family != "mysql" {
		t.Errorf("matchDBError = (%q, %v), want (mysql, true)", family, matched)
	}
}

func TestMatchDBError_PostgreSQL(t *testing.T) {
	family, matched := matchDBError("ERROR: syntax error at or near \"OR\" LINE 1")
	if !matched || family != "postgresql" {
		t.Errorf("matchDBError = (%q, %v), want (postgresql, true)", family, matched)
	}
}

func TestMatchDBError_MSSQL(t *testing.T) {
	family, matched := matchDBError("Unclosed quotation mark after the character string")
	if !matched || family != "mssql" {
		t.Errorf("matchDBError = (%q, %v), want (mssql, true)", family, matched)
	}
}

func TestMatchDBError_SQLite(t *testing.T) {
	family, matched := matchDBError(`sqlite3.OperationalError: near "OR": syntax error`)
	if !matched || family != "sqlite" {
		t.Errorf("matchDBError = (%q, %v), want (sqlite, true)", family, matched)
	}
}

func TestMatchDBError_Oracle(t *testing.T) {
	family, matched := matchDBError("ORA-00933: SQL command not properly ended")
	if !matched || family != "oracle" {
		t.Errorf("matchDBError = (%q, %v), want (oracle, true)", family, matched)
	}
}

func TestMatchDBError_Generic(t *testing.T) {
	family, matched := matchDBError("SQL syntax error near '''' (simulated)")
	if !matched || family != "generic" {
		t.Errorf("matchDBError = (%q, %v), want (generic, true)", family, matched)
	}
}

func TestMatchDBError_NoMatch(t *testing.T) {
	family, matched := matchDBError("results: (none)")
	if matched {
		t.Errorf("matchDBError = (%q, %v), want (\"\", false)", family, matched)
	}
}

func TestMatchDBError_CaseInsensitive(t *testing.T) {
	_, matched := matchDBError("YOU HAVE AN ERROR IN YOUR SQL SYNTAX")
	if !matched {
		t.Error("matchDBError should be case-insensitive")
	}
}

func TestMatchDBError_SpecificFamilyPreferredOverGeneric(t *testing.T) {
	// Contains both a MySQL-specific phrase AND a generic phrase -- the
	// specific family must win.
	family, matched := matchDBError("You have an error in your SQL syntax; check the manual")
	if !matched || family != "mysql" {
		t.Errorf("matchDBError = (%q, %v), want (mysql, true) -- specific family should take priority over generic", family, matched)
	}
}
