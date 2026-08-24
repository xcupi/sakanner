package cmdinjection

import (
	"fmt"
	"strings"
	"testing"
)

func TestCommandVariants_SmallAndBounded(t *testing.T) {
	variants := commandVariants()
	if len(variants) == 0 {
		t.Fatal("commandVariants returned no variants")
	}
	if len(variants) > 4 {
		t.Errorf("commandVariants returned %d variants, want at most 4 -- section 13 explicitly forbids dozens of payloads", len(variants))
	}
}

func TestCommandVariants_EachProducesTheLabCommandAndToken(t *testing.T) {
	for _, v := range commandVariants() {
		got := fmt.Sprintf(v.template, "TESTTOKEN123")
		if strings.Contains(got, "%!") {
			t.Errorf("variant %q: template produced a malformed fmt directive: %q -- the token was not substituted correctly", v.name, got)
		}
		if !strings.Contains(got, "TESTTOKEN123") {
			t.Errorf("variant %q: %q does not contain the token", v.name, got)
		}
		if !strings.Contains(got, labCommand) {
			t.Errorf("variant %q: %q does not contain the lab command name", v.name, got)
		}
	}
}

func TestCommandVariants_NamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range commandVariants() {
		if seen[v.name] {
			t.Errorf("duplicate variant name %q", v.name)
		}
		seen[v.name] = true
	}
}
