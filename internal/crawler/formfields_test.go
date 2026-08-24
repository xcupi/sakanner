package crawler

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Phase 3.13: FormRef.Fields -- discovering <input>/<select>/<textarea>
// names, types, and default values inside a <form>.

func TestCrawl_FormFields_TextHiddenPasswordInputs(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<form action="/login" method="post">
				<input name="username" type="text" value="">
				<input name="password" type="password">
				<input name="csrf_token" type="hidden" value="abc123">
			</form>
		</body></html>`))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(pages) != 1 || len(pages[0].Forms) != 1 {
		t.Fatalf("got %d pages, forms %+v", len(pages), pages)
	}
	fields := pages[0].Forms[0].Fields
	want := map[string]FormField{
		"username":   {Name: "username", Type: "text", Value: ""},
		"password":   {Name: "password", Type: "password", Value: ""},
		"csrf_token": {Name: "csrf_token", Type: "hidden", Value: "abc123"},
	}
	if len(fields) != len(want) {
		t.Fatalf("got %d fields, want %d: %+v", len(fields), len(want), fields)
	}
	for _, f := range fields {
		w, ok := want[f.Name]
		if !ok {
			t.Errorf("unexpected field %+v", f)
			continue
		}
		if f != w {
			t.Errorf("field %q = %+v, want %+v", f.Name, f, w)
		}
	}
}

func TestCrawl_FormFields_SelectUsesSelectedOptionOrFirst(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<form action="/filter" method="get">
				<select name="sort">
					<option value="asc">Ascending</option>
					<option value="desc" selected>Descending</option>
				</select>
				<select name="category">
					<option value="all">All</option>
					<option value="books">Books</option>
				</select>
			</form>
		</body></html>`))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	fields := pages[0].Forms[0].Fields
	byName := map[string]FormField{}
	for _, f := range fields {
		byName[f.Name] = f
	}
	if byName["sort"].Value != "desc" {
		t.Errorf("sort select value = %q, want %q (the explicitly selected option)", byName["sort"].Value, "desc")
	}
	if byName["category"].Value != "all" {
		t.Errorf("category select value = %q, want %q (first option, no explicit selection)", byName["category"].Value, "all")
	}
	if byName["sort"].Type != "select" || byName["category"].Type != "select" {
		t.Errorf("select fields did not get Type=select: %+v", fields)
	}
}

func TestCrawl_FormFields_Textarea(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<form action="/comment" method="post">
				<textarea name="body">  default comment text  </textarea>
			</form>
		</body></html>`))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	fields := pages[0].Forms[0].Fields
	if len(fields) != 1 {
		t.Fatalf("got %d fields, want 1: %+v", len(fields), fields)
	}
	if fields[0].Name != "body" || fields[0].Type != "textarea" || fields[0].Value != "default comment text" {
		t.Errorf("textarea field = %+v, want Name=body Type=textarea Value=\"default comment text\" (trimmed)", fields[0])
	}
}

func TestCrawl_FormFields_CheckboxAndRadio(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<form action="/prefs" method="post">
				<input type="checkbox" name="newsletter" value="yes">
				<input type="radio" name="plan" value="basic">
				<input type="radio" name="plan" value="pro" checked>
			</form>
		</body></html>`))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	fields := pages[0].Forms[0].Fields
	// Two <input name="plan"> entries are both collected (duplicate
	// names within one form are preserved here -- deduplication is
	// internal/parameters' job, not the crawler's, since collapsing
	// them here would lose which VALUE each radio option carries).
	if len(fields) != 3 {
		t.Fatalf("got %d fields, want 3 (newsletter + 2x plan): %+v", len(fields), fields)
	}
}

func TestCrawl_FormFields_SubmitAndButtonExcluded(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<form action="/login" method="post">
				<input name="username" type="text">
				<input type="submit" value="Log in">
				<button type="submit" name="action" value="login">Log in</button>
				<input type="reset" value="Clear">
				<input type="image" name="go" src="/go.png">
				<input type="file" name="upload">
			</form>
		</body></html>`))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	fields := pages[0].Forms[0].Fields
	if len(fields) != 1 || fields[0].Name != "username" {
		t.Fatalf("got fields %+v, want exactly [username] (submit/button/reset/image/file must all be excluded)", fields)
	}
}

// TestCrawl_FormFields_CheckboxWithoutValue_EmptyValueNotCrash is
// Phase 3.21's own adversarial item: an <input type="checkbox"> with
// no value="..." attribute at all (a real, common markup pattern --
// browsers submit "on" for it, but this crawler only ever records the
// OBSERVED default value present in markup, never a submission-time
// browser default) must still be discovered, with an empty Value, not
// skipped or crashed on.
func TestCrawl_FormFields_CheckboxWithoutValue_EmptyValueNotCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<form action="/prefs" method="post">
				<input type="checkbox" name="agree">
			</form>
		</body></html>`))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	fields := pages[0].Forms[0].Fields
	if len(fields) != 1 || fields[0].Name != "agree" || fields[0].Type != "checkbox" || fields[0].Value != "" {
		t.Fatalf("got fields %+v, want exactly one {agree checkbox \"\"}", fields)
	}
}

// TestCrawl_FormFields_MultipartEnctype_NonFileFieldsStillDiscovered
// proves discovery doesn't crash or silently drop a multipart form's
// non-file fields, even though this codebase never generates a
// genuine multipart/form-data body for mutation (multipart is not
// implemented anywhere -- see docs/phase-3-21-form-mutation.md section
// 1.14; file inputs specifically are already excluded by
// nonInputControlTypes, unchanged since Phase 3.13).
func TestCrawl_FormFields_MultipartEnctype_NonFileFieldsStillDiscovered(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<form action="/upload" method="post" enctype="multipart/form-data">
				<input type="text" name="description" value="a file">
				<input type="file" name="attachment">
			</form>
		</body></html>`))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	fields := pages[0].Forms[0].Fields
	if len(fields) != 1 || fields[0].Name != "description" {
		t.Fatalf("got fields %+v, want exactly [description] (the file input must still be excluded)", fields)
	}
}

func TestCrawl_FormFields_UnnamedInputsSkipped(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<form action="/x" method="post">
				<input type="text" value="no-name-here">
				<input name="real" type="text" value="v">
			</form>
		</body></html>`))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	fields := pages[0].Forms[0].Fields
	if len(fields) != 1 || fields[0].Name != "real" {
		t.Fatalf("got fields %+v, want exactly [real] (unnamed input must be skipped)", fields)
	}
}

func TestCrawl_FormFields_MalformedHTML_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><form action="/x" method="post"><input name="a"><select name="b"><input name="c" value="unterminated`))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(pages) != 1 {
		t.Fatalf("got %d pages, want 1 (malformed HTML must degrade gracefully, not abort)", len(pages))
	}
	// The exact field set the HTML tokenizer recovers from this
	// deliberately broken markup isn't the point -- surviving it
	// without a panic or error is.
	_ = pages[0].Forms
}

func TestCrawl_FormFields_TwoFormsFieldsNotMixed(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<form action="/login" method="post">
				<input name="username" type="text">
			</form>
			<form action="/search" method="get">
				<input name="q" type="text">
			</form>
		</body></html>`))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	forms := pages[0].Forms
	if len(forms) != 2 {
		t.Fatalf("got %d forms, want 2", len(forms))
	}
	if len(forms[0].Fields) != 1 || forms[0].Fields[0].Name != "username" {
		t.Errorf("first form fields = %+v, want exactly [username]", forms[0].Fields)
	}
	if len(forms[1].Fields) != 1 || forms[1].Fields[0].Name != "q" {
		t.Errorf("second form fields = %+v, want exactly [q]", forms[1].Fields)
	}
}
