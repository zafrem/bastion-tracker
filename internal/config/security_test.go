package config

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func hash(t *testing.T, pw string) string {
	t.Helper()
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func secureConfig(t *testing.T) *Config {
	c := Defaults()
	c.Storage.AuditSecret = strings.Repeat("a", 32)
	c.Auth.Enabled = true
	c.Auth.JWTSecret = strings.Repeat("j", 32)
	c.Auth.Users = []UserConfig{{Name: "admin", Password: hash(t, "S0me-strong-pw"), Role: "admin"}}
	return c
}

func TestValidateSecurity_AcceptsSecureConfig(t *testing.T) {
	if err := secureConfig(t).ValidateSecurity(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSecurity_DefaultsAreRejected(t *testing.T) {
	if err := Defaults().ValidateSecurity(); err == nil {
		t.Fatal("defaults (demo audit key) must not pass validation")
	}
}

func TestValidateSecurity_Rules(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *Config)
		want   string
	}{
		{"empty audit secret", func(c *Config) { c.Storage.AuditSecret = "" }, "audit_secret"},
		{"short audit secret", func(c *Config) { c.Storage.AuditSecret = "short" }, "audit_secret"},
		{"placeholder jwt secret", func(c *Config) { c.Auth.JWTSecret = "change-me-in-production" }, "jwt_secret"},
		{"short jwt secret", func(c *Config) { c.Auth.JWTSecret = "short" }, "jwt_secret"},
		{"plaintext password", func(c *Config) { c.Auth.Users[0].Password = "admin" }, "bcrypt"},
	}
	for _, tc := range cases {
		c := secureConfig(t)
		tc.mutate(c)
		err := c.ValidateSecurity()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err=%v, want mention of %q", tc.name, err, tc.want)
		}
	}
}

func TestValidateSecurity_AuthChecksSkippedWhenAuthDisabled(t *testing.T) {
	c := secureConfig(t)
	c.Auth.Enabled = false
	c.Auth.JWTSecret = "change-me-in-production"
	if err := c.ValidateSecurity(); err != nil {
		t.Errorf("auth disabled: jwt/user checks should be skipped, got %v", err)
	}
}

func TestValidateSecurity_DevModeBypasses(t *testing.T) {
	c := Defaults()
	c.DevMode = true
	if err := c.ValidateSecurity(); err != nil {
		t.Errorf("dev_mode must bypass checks, got %v", err)
	}
}

func TestLoad_EnvOverridesSecrets(t *testing.T) {
	t.Setenv("TRACKER_AUDIT_SECRET", strings.Repeat("e", 32))
	t.Setenv("TRACKER_JWT_SECRET", strings.Repeat("f", 32))
	c, err := Load("/nonexistent/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage.AuditSecret != strings.Repeat("e", 32) || c.Auth.JWTSecret != strings.Repeat("f", 32) {
		t.Error("env secrets were not applied")
	}
}
