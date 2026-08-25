package auth

import (
	"net/url"
	"testing"
)

// These tests cover extractLoginForm's handling of <input type="...">
// variants directly -- in particular, that a NAMED type="submit" field
// is now included in loginForm.Fields (the fix that makes
// submitCredentials actually send it), while button/image/reset/file
// remain excluded exactly as before. Some real-world applications gate
// their own login processing on their submit button's name being
// present in the POST body (a common server-side idiom, e.g. PHP's
// own isset($_POST['Login'])) -- a form whose submit button was
// silently dropped from the submission would authenticate against
// such an application even though no real browser ever sends that
// exact request.

func mustParseTestBase(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse("http://example.test/login")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	return u
}

func TestExtractLoginForm_NamedSubmitButton_IsIncludedInFields(t *testing.T) {
	body := []byte(`<html><body><form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" name="Login" value="Log in">
</form></body></html>`)
	form, err := findLoginForm(body, mustParseTestBase(t))
	if err != nil {
		t.Fatalf("findLoginForm: %v", err)
	}
	v, ok := form.Fields["Login"]
	if !ok {
		t.Fatal(`named type="submit" field "Login" is missing from Fields -- a server that gates login processing on this field's presence (e.g. PHP's isset($_POST['Login'])) would reject this submission`)
	}
	if v != "Log in" {
		t.Errorf(`Fields["Login"] = %q, want "Log in"`, v)
	}
}

func TestExtractLoginForm_UnnamedSubmitButton_IsNotIncluded(t *testing.T) {
	body := []byte(`<html><body><form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" value="Log in">
</form></body></html>`)
	form, err := findLoginForm(body, mustParseTestBase(t))
	if err != nil {
		t.Fatalf("findLoginForm: %v", err)
	}
	for k, v := range form.Fields {
		if v == "Log in" {
			t.Errorf("an unnamed submit input must not appear in Fields under any key, found Fields[%q] = %q", k, v)
		}
	}
	if len(form.Fields) != 2 {
		t.Errorf("Fields = %v, want exactly username and password (2 entries)", form.Fields)
	}
}

func TestExtractLoginForm_ButtonImageResetFile_RemainExcludedEvenWhenNamed(t *testing.T) {
	body := []byte(`<html><body><form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="button" name="btn" value="ButtonVal">
  <input type="image" name="img" value="ImageVal">
  <input type="reset" name="rst" value="ResetVal">
  <input type="file" name="upload" value="FileVal">
</form></body></html>`)
	form, err := findLoginForm(body, mustParseTestBase(t))
	if err != nil {
		t.Fatalf("findLoginForm: %v", err)
	}
	for _, excludedName := range []string{"btn", "img", "rst", "upload"} {
		if _, ok := form.Fields[excludedName]; ok {
			t.Errorf("Fields unexpectedly contains %q -- button/image/reset/file inputs must remain excluded", excludedName)
		}
	}
	if len(form.Fields) != 2 {
		t.Errorf("Fields = %v, want exactly username and password (2 entries)", form.Fields)
	}
}

func TestExtractLoginForm_HiddenAndTextFields_StillIncluded(t *testing.T) {
	body := []byte(`<html><body><form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="text" name="username" value="">
  <input type="password" name="password">
  <input type="submit" name="do_login" value="Go">
</form></body></html>`)
	form, err := findLoginForm(body, mustParseTestBase(t))
	if err != nil {
		t.Fatalf("findLoginForm: %v", err)
	}
	if form.Fields["csrf_token"] != "abc123" {
		t.Errorf(`Fields["csrf_token"] = %q, want "abc123"`, form.Fields["csrf_token"])
	}
	if !form.HasPassword {
		t.Error("HasPassword = false, want true (a password-type input is present)")
	}
	if form.Fields["do_login"] != "Go" {
		t.Errorf(`Fields["do_login"] = %q, want "Go"`, form.Fields["do_login"])
	}
}
