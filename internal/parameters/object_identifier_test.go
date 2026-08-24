package parameters

import "testing"

func TestIsLikelyObjectIdentifier_KnownObjectNames_True(t *testing.T) {
	for _, name := range []string{
		"id", "user_id", "account_id", "order_id", "document_id",
		"invoice_id", "profile_id", "customer_id", "resource_id",
		"item_id", "object_id", "note_id", "doc_id", "userId", "accountId",
		"ID", "User_Id",
	} {
		if !IsLikelyObjectIdentifier(name) {
			t.Errorf("IsLikelyObjectIdentifier(%q) = false, want true", name)
		}
	}
}

// TestIsLikelyObjectIdentifier_Adversarial_False covers task section
// 15's own adversarial parameter-name cases (pagination, version,
// timestamp, non-object) plus ordinary English words that merely END
// in "id" -- the exact false-positive class a naive case-insensitive
// "id" suffix check would wrongly match (see
// docs/phase-3-24-authorization.md section 8).
func TestIsLikelyObjectIdentifier_Adversarial_False(t *testing.T) {
	for _, name := range []string{
		"page", "limit", "offset", "per_page", "size",
		"version", "v", "api_version",
		"timestamp", "ts", "date", "time",
		"lang", "locale", "format", "sort", "order", "callback",
		"valid", "paid", "grid", "avoid", "solid", "void",
		"", "   ",
	} {
		if IsLikelyObjectIdentifier(name) {
			t.Errorf("IsLikelyObjectIdentifier(%q) = true, want false", name)
		}
	}
}

func TestIsLikelyObjectIdentifier_CaseInsensitiveDenylist(t *testing.T) {
	for _, name := range []string{"Page", "PAGE", "Order", "VERSION"} {
		if IsLikelyObjectIdentifier(name) {
			t.Errorf("IsLikelyObjectIdentifier(%q) = true, want false (denylist must be case-insensitive)", name)
		}
	}
}

func TestIsLikelyObjectIdentifier_OrderVsOrderID_Distinguished(t *testing.T) {
	// The exact adversarial pair task section 15/docs section 8 calls
	// out by name: "order" (a sort-direction parameter) must never be
	// confused with "order_id" (a genuine object reference), even
	// though both share the substring "order".
	if IsLikelyObjectIdentifier("order") {
		t.Error(`IsLikelyObjectIdentifier("order") = true, want false`)
	}
	if !IsLikelyObjectIdentifier("order_id") {
		t.Error(`IsLikelyObjectIdentifier("order_id") = false, want true`)
	}
}
