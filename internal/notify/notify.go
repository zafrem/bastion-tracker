// Package notify provides alert notification channels for Bastion-Tracker.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Notifier sends an alert notification to an external channel.
type Notifier interface {
	Notify(ruleName, message, severity string) error
}

// Noop discards notifications; used when no channel is configured.
type Noop struct{}

func (Noop) Notify(_, _, _ string) error { return nil }

// SlackNotifier posts to a Slack incoming webhook URL.
type SlackNotifier struct {
	WebhookURL string
}

func (s *SlackNotifier) Notify(ruleName, message, severity string) error {
	emoji := ":warning:"
	if severity == "critical" {
		emoji = ":rotating_light:"
	}
	payload := map[string]string{
		"text": fmt.Sprintf("%s *[%s]* %s — %s", emoji, strings.ToUpper(severity), ruleName, message),
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(s.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack: %w", err)
	}
	return finishPost("slack", resp)
}

// EmailNotifier sends alert notifications via SMTP.
type EmailNotifier struct {
	SMTPHost string
	SMTPPort int
	From     string
	To       []string
	Username string
	Password string
}

// headerSafe strips CR and LF so a value can never end the header line and
// inject extra headers or a new body.
func headerSafe(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}

// maxBodyBytes bounds the alert text placed in an email so a huge event cannot produce a huge message.
const maxBodyBytes = 8 * 1024

// bodySafe makes alert text safe to place in a plain-text email body: control characters other than tab and
// newline are dropped (they have no place in text and some mail systems act on them), line endings are
// normalised, and the length is bounded. The text is never interpreted as markup because the message is sent
// as text/plain.
func bodySafe(v string) string {
	v = strings.ReplaceAll(strings.ReplaceAll(v, "\r\n", "\n"), "\r", "\n")
	v = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			return r
		}
		return -1
	}, v)
	if len(v) > maxBodyBytes {
		v = strings.ToValidUTF8(v[:maxBodyBytes], "") + "\n[truncated]"
	}
	return strings.ReplaceAll(v, "\n", "\r\n")
}

// validAddress accepts a plain address (not "Name <addr>" and not a list) and nothing containing line breaks.
func validAddress(a string) bool {
	if strings.ContainsAny(a, "\r\n") {
		return false
	}
	parsed, err := mail.ParseAddress(a)
	return err == nil && parsed.Address == a
}

func (e *EmailNotifier) Notify(ruleName, message, severity string) error {
	if !validAddress(e.From) {
		return fmt.Errorf("email: invalid sender")
	}
	to := make([]string, len(e.To))
	for i, a := range e.To {
		if !validAddress(a) {
			return fmt.Errorf("email: invalid recipient")
		}
		to[i] = a
	}
	ruleName, severity = headerSafe(ruleName), headerSafe(severity)
	addr := fmt.Sprintf("%s:%d", e.SMTPHost, e.SMTPPort)
	subject := fmt.Sprintf("[%s] Bastion Alert: %s", strings.ToUpper(severity), ruleName)
	body := fmt.Sprintf("Subject: %s\r\nFrom: %s\r\nTo: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n\r\nTime: %s\r\n",
		subject, e.From, strings.Join(to, ", "), bodySafe(message), time.Now().Format(time.RFC3339))
	var a smtp.Auth
	if e.Username != "" {
		a = smtp.PlainAuth("", e.Username, e.Password, e.SMTPHost)
	}
	return smtp.SendMail(addr, a, e.From, e.To, []byte(body))
}

// WebhookNotifier POSTs a JSON payload to a generic HTTP endpoint.
type WebhookNotifier struct {
	URL string
}

func (wh *WebhookNotifier) Notify(ruleName, message, severity string) error {
	payload := map[string]string{
		"rule":     ruleName,
		"message":  message,
		"severity": severity,
		"time":     time.Now().Format(time.RFC3339),
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(wh.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	return finishPost("webhook", resp)
}

// Multi fans out to multiple notifiers and collects all errors.
type Multi struct {
	notifiers []Notifier
}

// NewMulti creates a Multi notifier from the given notifiers.
func NewMulti(notifiers ...Notifier) *Multi {
	return &Multi{notifiers: notifiers}
}

func (m *Multi) Notify(ruleName, message, severity string) error {
	var errs []string
	for _, n := range m.notifiers {
		if err := n.Notify(ruleName, message, severity); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("notify errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// finishPost closes the response and reports a non-2xx status as a failed delivery. Without the status
// check a rejected webhook (revoked URL, 404, 500) would be counted as sent.
func finishPost(kind string, resp *http.Response) error {
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: unexpected status %s", kind, resp.Status)
	}
	return nil
}
