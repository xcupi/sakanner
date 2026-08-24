package sstiactive

import "fmt"

// templateVariant pairs a bounded, fixed template-engine syntax with
// the payload string produced for one (a, b) operand pair.
type templateVariant struct {
	name    string
	payload string
}

// templateVariants returns the small, fixed set of template-engine
// delimiter syntaxes tried against every target -- Jinja2/Twig/
// Mustache-style, Freemarker/JSP-EL/Thymeleaf-style, Ruby-style, and
// ERB/JSP-scriptlet-style -- covering the delimiter shapes real
// template engines use, mirroring cmdinjectionactive's own "small,
// bounded, fixed variant set tried unconditionally" precedent (never
// an unbounded/engine-fingerprint-driven search).
func templateVariants(a, b int) []templateVariant {
	return []templateVariant{
		{name: "jinja2/twig/mustache", payload: fmt.Sprintf("{{%d*%d}}", a, b)},
		{name: "freemarker/jsp-el/thymeleaf", payload: fmt.Sprintf("${%d*%d}", a, b)},
		{name: "ruby/jsf", payload: fmt.Sprintf("#{%d*%d}", a, b)},
		{name: "erb/jsp-scriptlet", payload: fmt.Sprintf("<%%= %d*%d %%>", a, b)},
	}
}
