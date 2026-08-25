package auth

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// loginForm is the minimal shape this package extracts from a fetched
// login page -- deliberately its own small type, not
// internal/crawler.FormRef: task section 9 requires the authentication
// layer to stay independent from the crawler's implementation, so this
// file re-parses the page itself (using the same golang.org/x/net/html
// dependency the crawler also happens to use -- a shared library
// dependency, not a package dependency on internal/crawler) rather than
// importing crawler's own form-discovery code.
type loginForm struct {
	Action      string
	Method      string
	Fields      map[string]string // every named input/textarea/select field found, with its ORIGINAL value (hidden CSRF tokens survive here unless overwritten by the caller)
	HasPassword bool              // true if any <input type="password"> was found in this form
	// InputMeta additionally captures, for every <input> element also
	// present in Fields, the metadata discover.go's login-form/
	// username-field scoring heuristics need (type/autocomplete/id and
	// any associated <label for="id">'s text). Populated unconditionally
	// by extractLoginForm (one extra pass over the form's own children,
	// bounded by the same page-size limit every caller already reads
	// under) but only ever READ by discover.go -- the existing
	// form_login path (FormLoginProvider, unchanged) only ever reads
	// Action/Method/Fields/HasPassword, exactly as before this field
	// was added.
	InputMeta []inputMeta
}

// inputMeta is one <input>'s discovery-relevant metadata. Order matches
// document order, which discover.go's tie-breaking relies on.
type inputMeta struct {
	Name         string
	Type         string // the input's own "type" attribute, lowercased ("text" if absent)
	Autocomplete string // lowercased "autocomplete" attribute, if any
	ID           string
	Label        string // associated <label for="id">'s text content, if any (empty if none)
}

// findLoginForm parses body (the login page's HTML) and returns the
// form most likely to be the login form: the first <form> containing a
// password-type input if any exists, otherwise the first <form> found
// at all. Returns an error if the page contains no <form> element --
// task section 4's flow explicitly requires identifying a login form
// before anything can be submitted; a page with no form at all cannot
// honestly be treated as one (see docs/phase-3-14-authentication.md
// "Limitations": a JSON-only or JS-rendered login page is not supported
// in this phase).
func findLoginForm(body []byte, base *url.URL) (loginForm, error) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return loginForm{}, fmt.Errorf("auth: parse login page HTML: %w", err)
	}

	forms := parseForms(doc, base)
	if len(forms) == 0 {
		return loginForm{}, fmt.Errorf("auth: no <form> found on the login page")
	}
	for _, f := range forms {
		if f.HasPassword {
			return f, nil
		}
	}
	return forms[0], nil
}

// parseForms returns every <form> found in doc, extracted via
// extractLoginForm -- factored out of findLoginForm above so
// discover.go's own multi-form scoring (it needs every form on a page,
// not just findLoginForm's own single "first form with a password, or
// else the first form" pick) can reuse the exact same walk/extraction
// logic rather than a second, separately-maintained implementation.
// findLoginForm's own external behavior is unchanged by this split.
func parseForms(doc *html.Node, base *url.URL) []loginForm {
	var forms []loginForm
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			forms = append(forms, extractLoginForm(n, base))
			// Do not recurse into a form's own children here -- nested
			// forms are invalid HTML and extractLoginForm already walks
			// this form's subtree itself.
			return
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return forms
}

func extractLoginForm(form *html.Node, base *url.URL) loginForm {
	actionAttr, _ := attr(form, "action")
	action := base.String()
	if actionAttr != "" {
		if u, err := url.Parse(actionAttr); err == nil {
			action = base.ResolveReference(u).String()
		}
	}
	method, ok := attr(form, "method")
	if !ok || method == "" {
		method = "GET"
	}

	labels := collectLabels(form)

	fields := map[string]string{}
	var metas []inputMeta
	hasPassword := false
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input":
				name, ok := attr(n, "name")
				typ, _ := attr(n, "type")
				typ = strings.ToLower(strings.TrimSpace(typ))
				if ok && name != "" && typ != "submit" && typ != "button" && typ != "image" && typ != "reset" && typ != "file" {
					value, _ := attr(n, "value")
					fields[name] = value
					if typ == "password" {
						hasPassword = true
					}
					id, _ := attr(n, "id")
					autocomplete, _ := attr(n, "autocomplete")
					metaType := typ
					if metaType == "" {
						metaType = "text" // matches the browser default for <input> with no type attribute
					}
					metas = append(metas, inputMeta{
						Name: name, Type: metaType, Autocomplete: strings.ToLower(strings.TrimSpace(autocomplete)),
						ID: id, Label: labels[id],
					})
				}
				return
			case "textarea":
				if name, ok := attr(n, "name"); ok && name != "" {
					fields[name] = textNodeContent(n)
				}
				return
			case "select":
				if name, ok := attr(n, "name"); ok && name != "" {
					fields[name] = selectedValue(n)
				}
				return
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	for child := form.FirstChild; child != nil; child = child.NextSibling {
		walk(child)
	}

	return loginForm{Action: action, Method: strings.ToUpper(method), Fields: fields, HasPassword: hasPassword, InputMeta: metas}
}

// collectLabels walks form's entire subtree and returns a map of
// "for" attribute -> the referenced <label>'s own text content, for
// every <label for="..."> found. Labels can appear anywhere within the
// form relative to the input they describe (before, after, unrelated
// document order), so this is deliberately a separate, complete pass
// over the form rather than something threaded through the single
// forward walk in extractLoginForm above.
func collectLabels(form *html.Node) map[string]string {
	labels := map[string]string{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "label" {
			if forAttr, ok := attr(n, "for"); ok && forAttr != "" {
				if text := textNodeContent(n); text != "" {
					labels[forAttr] = text
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(form)
	return labels
}

func attr(n *html.Node, name string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val, true
		}
	}
	return "", false
}

func textNodeContent(n *html.Node) string {
	var b strings.Builder
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			b.WriteString(child.Data)
		}
	}
	return strings.TrimSpace(b.String())
}

func selectedValue(sel *html.Node) string {
	var first, selected *html.Node
	for child := sel.FirstChild; child != nil; child = child.NextSibling {
		if child.Type != html.ElementNode || child.Data != "option" {
			continue
		}
		if first == nil {
			first = child
		}
		if _, ok := attr(child, "selected"); ok {
			selected = child
			break
		}
	}
	target := selected
	if target == nil {
		target = first
	}
	if target == nil {
		return ""
	}
	if v, ok := attr(target, "value"); ok {
		return v
	}
	return textNodeContent(target)
}
