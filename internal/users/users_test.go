package users

import (
	"testing"

	"github.com/bastion/tracker/internal/config"
)

func seeded() *Manager {
	return New([]config.UserConfig{
		{Name: "admin", Password: "admin", Role: "admin"},
		{Name: "ops", Password: "ops", Role: "operator"},
		{Name: "viewer", Password: "viewer", Role: "viewer"},
	})
}

func TestNew_SeedsAndSkipsEmpty(t *testing.T) {
	m := New([]config.UserConfig{
		{Name: "admin", Password: "admin", Role: "admin"},
		{Name: "", Password: "x", Role: "viewer"}, // skipped
	})
	if got := len(m.List()); got != 1 {
		t.Fatalf("expected 1 user, got %d", got)
	}
}

func TestList_SortedAndPasswordFree(t *testing.T) {
	m := seeded()
	list := m.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 users, got %d", len(list))
	}
	if list[0].Name != "admin" || list[1].Name != "ops" || list[2].Name != "viewer" {
		t.Fatalf("users not sorted by name: %+v", list)
	}
	// User struct has no password field — nothing to leak by construction.
}

func TestVerify_PlaintextSeed(t *testing.T) {
	m := seeded()
	if role, ok := m.Verify("ops", "ops"); !ok || role != "operator" {
		t.Fatalf("expected operator login to succeed, got role=%q ok=%v", role, ok)
	}
	if _, ok := m.Verify("ops", "wrong"); ok {
		t.Fatal("expected wrong password to fail")
	}
	if _, ok := m.Verify("nobody", "x"); ok {
		t.Fatal("expected unknown user to fail")
	}
}

func TestCreate_HashesAndVerifies(t *testing.T) {
	m := seeded()
	u, err := m.Create("alice", "s3cret", "operator")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.Name != "alice" || u.Role != "operator" {
		t.Fatalf("unexpected user: %+v", u)
	}
	if role, ok := m.Verify("alice", "s3cret"); !ok || role != "operator" {
		t.Fatalf("expected bcrypt login to succeed, got role=%q ok=%v", role, ok)
	}
	if _, ok := m.Verify("alice", "s3cret-wrong"); ok {
		t.Fatal("expected wrong bcrypt password to fail")
	}
}

func TestCreate_Validation(t *testing.T) {
	m := seeded()
	cases := []struct {
		name, pw, role string
		want           error
	}{
		{"", "x", "viewer", ErrEmptyName},
		{"bob", "", "viewer", ErrEmptyPassword},
		{"bob", "x", "wizard", ErrInvalidRole},
		{"admin", "x", "viewer", ErrExists},
	}
	for _, c := range cases {
		if _, err := m.Create(c.name, c.pw, c.role); err != c.want {
			t.Errorf("Create(%q,_,%q) = %v, want %v", c.name, c.role, err, c.want)
		}
	}
}

func TestUpdateRole_And_LastAdminGuard(t *testing.T) {
	m := seeded()
	if _, err := m.UpdateRole("ops", "admin"); err != nil {
		t.Fatalf("promote ops: %v", err)
	}
	// Now two admins; demoting one is allowed.
	if _, err := m.UpdateRole("admin", "viewer"); err != nil {
		t.Fatalf("demote one of two admins: %v", err)
	}
	// Only "ops" is admin now; demoting it must fail.
	if _, err := m.UpdateRole("ops", "viewer"); err != ErrLastAdmin {
		t.Fatalf("expected ErrLastAdmin, got %v", err)
	}
	if _, err := m.UpdateRole("ghost", "viewer"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSetPassword(t *testing.T) {
	m := seeded()
	if err := m.SetPassword("viewer", "newpass"); err != nil {
		t.Fatalf("set password: %v", err)
	}
	if _, ok := m.Verify("viewer", "viewer"); ok {
		t.Fatal("old password should no longer work")
	}
	if role, ok := m.Verify("viewer", "newpass"); !ok || role != "viewer" {
		t.Fatalf("new password should work, got role=%q ok=%v", role, ok)
	}
	if err := m.SetPassword("viewer", ""); err != ErrEmptyPassword {
		t.Fatalf("expected ErrEmptyPassword, got %v", err)
	}
	if err := m.SetPassword("ghost", "x"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDelete_And_LastAdminGuard(t *testing.T) {
	m := seeded()
	if err := m.Delete("viewer"); err != nil {
		t.Fatalf("delete viewer: %v", err)
	}
	if _, err := m.Get("viewer"); err != ErrNotFound {
		t.Fatalf("expected viewer gone, got %v", err)
	}
	// Only one admin remains; deleting it must fail.
	if err := m.Delete("admin"); err != ErrLastAdmin {
		t.Fatalf("expected ErrLastAdmin, got %v", err)
	}
	if err := m.Delete("ghost"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
