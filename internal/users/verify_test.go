package users

import (
	"testing"

	"github.com/bastion/tracker/internal/config"
)

func TestVerify_PlaintextSeedStillWorks(t *testing.T) {
	m := New([]config.UserConfig{{Name: "ops", Password: "ops", Role: "operator"}})
	if role, ok := m.Verify("ops", "ops"); !ok || role != "operator" {
		t.Errorf("valid plaintext login failed: %q %v", role, ok)
	}
	if _, ok := m.Verify("ops", "opS"); ok {
		t.Error("wrong password accepted")
	}
	if _, ok := m.Verify("ops", ""); ok {
		t.Error("empty password accepted")
	}
}
