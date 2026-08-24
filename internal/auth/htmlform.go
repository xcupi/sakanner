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

	fields := map[string]string{}
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

	return loginForm{Action: action, Method: strings.ToUpper(method), Fields: fields, HasPassword: hasPassword}
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
