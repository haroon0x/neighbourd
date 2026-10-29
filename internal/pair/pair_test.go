package pair

import (
	"strings"
	"testing"
	"time"
)

func TestCodeShape(t *testing.T) {
	_, code, err := NewWindow(time.Minute)
	if err != nil {
		t.Fatalf("NewWindow: %v", err)
	}
	if len(code) != CodeLength {
		t.Errorf("code %q is %d chars, want %d", code, len(code), CodeLength)
	}
	for _, r := range code {
		if !strings.ContainsRune(codeAlphabet, r) {
			t.Errorf("code %q contains %q, which is not in the alphabet", code, r)
		}
	}
	if strings.ContainsAny(code, "0O1IL") {
		t.Errorf("code %q contains a character that is easy to misread", code)
	}
}

func TestRedeemIsSingleUse(t *testing.T) {
	w, code, err := NewWindow(time.Minute)
	if err != nil {
		t.Fatalf("NewWindow: %v", err)
	}
	if !w.Redeem(code) {
		t.Fatal("a fresh code was rejected")
	}
	if w.Redeem(code) {
		t.Error("the same code was accepted twice")
	}
	if w.Open() {
		t.Error("window is still open after a successful redeem")
	}
}

func TestRedeemRejectsWrongCode(t *testing.T) {
	w, code, err := NewWindow(time.Minute)
	if err != nil {
		t.Fatalf("NewWindow: %v", err)
	}
	if w.Redeem("ZZZZZZZZ") && code != "ZZZZZZZZ" {
		t.Error("a wrong code was accepted")
	}
	if !w.Open() {
		t.Error("a wrong attempt closed the window; the operator should get another try")
	}
}

func TestRedeemAcceptsLowercaseAndSpaces(t *testing.T) {
	w, code, err := NewWindow(time.Minute)
	if err != nil {
		t.Fatalf("NewWindow: %v", err)
	}
	messy := strings.ToLower(code[:4]) + " " + strings.ToLower(code[4:])
	if !w.Redeem(messy) {
		t.Errorf("code %q was rejected when typed as %q", code, messy)
	}
}

func TestExpiry(t *testing.T) {
	w, code, err := NewWindow(time.Nanosecond)
	if err != nil {
		t.Fatalf("NewWindow: %v", err)
	}
	time.Sleep(time.Millisecond)
	if w.Redeem(code) {
		t.Error("an expired code was accepted")
	}
	if w.Open() {
		t.Error("window reports open after expiry")
	}
}

func TestCloseEndsWindow(t *testing.T) {
	w, code, err := NewWindow(time.Minute)
	if err != nil {
		t.Fatalf("NewWindow: %v", err)
	}
	w.Close()
	if w.Redeem(code) {
		t.Error("a closed window accepted a code")
	}
}

func TestReopenInvalidatesPreviousCode(t *testing.T) {
	w, first, err := NewWindow(time.Minute)
	if err != nil {
		t.Fatalf("NewWindow: %v", err)
	}
	second, err := w.Reopen(time.Minute)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	if first == second {
		t.Fatal("Reopen produced the same code")
	}
	if w.Redeem(first) {
		t.Error("the previous code still works after Reopen")
	}
	if !w.Redeem(second) {
		t.Error("the new code does not work")
	}
}

func TestZeroTTLFallsBackToDefault(t *testing.T) {
	w, _, err := NewWindow(0)
	if err != nil {
		t.Fatalf("NewWindow: %v", err)
	}
	if got := time.Until(w.ExpiresAt()); got > DefaultTTL {
		t.Errorf("window expires in %s, longer than the default %s", got, DefaultTTL)
	}
}
