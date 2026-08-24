package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adrg/xdg"
)

func TestAuthMetadataRejectsPlaintext(t *testing.T) {
	previousStateHome := xdg.StateHome
	xdg.StateHome = t.TempDir()
	t.Cleanup(func() { xdg.StateHome = previousStateHome })
	path := filepath.Join(xdg.StateHome, "goat", "auth-session.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"did":"did:plc:test","password":"secret","access_token":"access","session_token":"refresh","pds":"https://example.com"}`)
	if err := os.WriteFile(path, plaintext, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthMetadataFile(); err == nil {
		t.Fatal("plaintext session metadata was accepted")
	}
	var session AuthSession
	if err := decodeStrictJSON([]byte(`{} {}`), &session); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}
