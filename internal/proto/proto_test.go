package proto

import "testing"

// The canonical forms are a contract with every other implementation, including
// the version of this one you replaced. These are golden strings: if they
// change, peers stop verifying and the change needs a new protocol id.
func TestCanonicalRequestGolden(t *testing.T) {
	got := string(Request("GET", "/v1/ping", "1793000000", "ab", nil))

	want := "neighbourd/req/v1\n" +
		"GET\n" +
		"/v1/ping\n" +
		"1793000000\n" +
		"ab\n" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	if got != want {
		t.Fatalf("canonical request drifted from docs/PROTOCOL.md\n got: %q\nwant: %q", got, want)
	}
}

func TestCanonicalPairingGolden(t *testing.T) {
	got := string(Pairing([]byte(`{"id":"x"}`)))
	want := "neighbourd/pair/v1\n" + BodyHash([]byte(`{"id":"x"}`))
	if got != want {
		t.Fatalf("canonical pairing form drifted\n got: %q\nwant: %q", got, want)
	}
}

func TestRequestCoversTargetAndBody(t *testing.T) {
	base := Request("GET", "/v1/ping", "1", "n", nil)

	if string(base) == string(Request("GET", "/v1/identity", "1", "n", nil)) {
		t.Error("path is not covered by the signature")
	}
	if string(base) == string(Request("GET", "/v1/ping?a=1", "1", "n", nil)) {
		t.Error("query string is not covered by the signature")
	}
	if string(base) == string(Request("POST", "/v1/ping", "1", "n", nil)) {
		t.Error("method is not covered by the signature")
	}
	if string(base) == string(Request("GET", "/v1/ping", "2", "n", nil)) {
		t.Error("timestamp is not covered by the signature")
	}
	if string(base) == string(Request("GET", "/v1/ping", "1", "m", nil)) {
		t.Error("nonce is not covered by the signature")
	}
	if string(base) == string(Request("GET", "/v1/ping", "1", "n", []byte("{}"))) {
		t.Error("body is not covered by the signature")
	}
}

func TestBodyHashIsHexSha256(t *testing.T) {
	if got := BodyHash(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("BodyHash(nil) = %s, want the sha256 of the empty string", got)
	}
	if len(BodyHash([]byte("x"))) != 64 {
		t.Error("BodyHash is not 64 hex chars")
	}
}

func TestDomainSeparation(t *testing.T) {
	// A signature made for pairing must not be reusable as a request signature.
	req := string(Request("POST", "/v1/pair/request", "", "", []byte("body")))
	pair := string(Pairing([]byte("body")))
	if req == pair {
		t.Fatal("request and pairing canonical forms collide")
	}
	if !contains(req, "neighbourd/req/v1") || !contains(pair, "neighbourd/pair/v1") {
		t.Error("canonical forms are not domain separated by prefix")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
