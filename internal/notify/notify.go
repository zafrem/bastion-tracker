// Package notify provides alert notification channels for Bastion-Tracker.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
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
	resp.Body.Close()
	return nil
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

func (e *EmailNotifier) Notify(ruleName, message, severity string) error {
	addr := fmt.Sprintf("%s:%d", e.SMTPHost, e.SMTPPort)
	subject := fmt.Sprintf("[%s] Bastion Alert: %s", strings.ToUpper(severity), ruleName)
	body := fmt.Sprintf("Subject: %s\r\nFrom: %s\r\nTo: %s\r\n\r\n%s\r\n\r\nTime: %s\r\n",
		subject, e.From, strings.Join(e.To, ", "), message, time.Now().Format(time.RFC3339))
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
	resp.Body.Close()
	return nil
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
