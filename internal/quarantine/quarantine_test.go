package quarantine

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/arphost/sentinelmail-gateway/internal/bootstrap"
)

func TestReleaseHeldForRecipientDeliversStoredBlob(t *testing.T) {
	dsn := os.Getenv("SMG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set SMG_TEST_DATABASE_URL to run quarantine release integration test")
	}
	ctx := context.Background()
	if err := bootstrap.MigrateAndSeed(ctx, dsn); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	defer db.Close()

	server := startSMTPTestServer(t)
	defer server.Close()

	orgID := uuid.New()
	domainID := uuid.New()
	userID := uuid.New()
	mailLogID := uuid.New()
	quarantineID := uuid.New()
	raw := []byte("From: sender@example.net\r\nTo: victim@example.com\r\nSubject: held\r\n\r\nbody\r\n")

	_, err = db.Exec(ctx, `
		INSERT INTO organizations (id, name, slug) VALUES ($1, 'Test Org', $2);
		INSERT INTO users (id, organization_id, email, password_hash, role) VALUES ($3, $1, $4, 'unused', 'org_admin');
		INSERT INTO domains (id, organization_id, name) VALUES ($5, $1, $6);
		INSERT INTO gateways (organization_id, domain_id, kind, host, port, use_tls, priority, is_active)
		VALUES ($1, $5, 'smtp_relay', '127.0.0.1', $7, false, 1, true);
		INSERT INTO mail_logs (id, organization_id, domain_id, direction, from_addr, to_addrs, subject, rspamd_score, disposition, received_at)
		VALUES ($8, $1, $5, 'inbound', 'sender@example.net', ARRAY['victim@example.com'], 'held', 9, 'quarantined', now());
		INSERT INTO quarantine_entries (id, organization_id, mail_log_id, domain_id, from_addr, to_addr, subject, rspamd_score, storage_key, state, received_at)
		VALUES ($9, $1, $8, $5, 'sender@example.net', 'victim@example.com', 'held', 9, 'db', 'held', now());
		INSERT INTO quarantine_blobs (quarantine_entry_id, organization_id, mail_log_id, message_bytes)
		VALUES ($9, $1, $8, $10);
	`, orgID, "test-"+orgID.String(), userID, "admin-"+userID.String()+"@example.com", domainID, "example.com", server.Port, mailLogID, quarantineID, raw)
	if err != nil {
		t.Fatalf("seed release case: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	ok, err := ReleaseHeldForRecipient(ctx, db, mailLogID, "victim@example.com", userID)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if !ok {
		t.Fatal("release returned ok=false")
	}
	select {
	case got := <-server.Messages:
		if !strings.Contains(got, "Subject: held") || !strings.Contains(got, "body") {
			t.Fatalf("released message body mismatch: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("smtp test server did not receive released message")
	}
	var state string
	if err := db.QueryRow(ctx, `SELECT state::text FROM quarantine_entries WHERE id = $1`, quarantineID).Scan(&state); err != nil {
		t.Fatalf("read released state: %v", err)
	}
	if state != "released" {
		t.Fatalf("state = %q, want released", state)
	}
}

func TestRDAPAbuseContactExtraction(t *testing.T) {
	doc := rdapDoc{Entities: []rdapEntity{
		{
			Roles: []string{"registrant"},
			Entities: []rdapEntity{{
				Roles: []string{"abuse"},
				VCard: []any{"vcard", []any{
					[]any{"fn", map[string]any{}, "text", "Abuse Desk"},
					[]any{"email", map[string]any{}, "text", "Abuse@Example.NET"},
				}},
			}},
		},
	}}
	got := uniqueEmails(doc.collectAbuseEmails(nil))
	if len(got) != 1 || got[0] != "abuse@example.net" {
		t.Fatalf("abuse contacts = %#v, want abuse@example.net", got)
	}
}

func TestValidateRDAPRedirectAllowsHTTPS(t *testing.T) {
	req := &http.Request{URL: mustURL(t, "https://rdap.arin.net/registry/ip/69.171.232.151")}
	if err := validateRDAPRedirect(req, []*http.Request{{URL: mustURL(t, "https://rdap.org/ip/69.171.232.151")}}); err != nil {
		t.Fatalf("validate https redirect: %v", err)
	}
}

func TestValidateRDAPRedirectRejectsHTTP(t *testing.T) {
	req := &http.Request{URL: mustURL(t, "http://rdap.arin.net/registry/ip/69.171.232.151")}
	if err := validateRDAPRedirect(req, nil); err == nil {
		t.Fatal("accepted non-https RDAP redirect")
	}
}

func TestLookupRDAPFallsBackAcrossTrustedRegistries(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "slow registry unavailable", http.StatusGatewayTimeout)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{
			"name": "Example Network",
			"entities": [{
				"roles": ["abuse"],
				"vcardArray": ["vcard", [
					["fn", {}, "text", "Abuse Desk"],
					["email", {}, "text", "abuse@example.net"]
				]]
			}]
		}`))
	}))
	defer second.Close()

	orig := rdapEndpointTemplates
	rdapEndpointTemplates = []string{first.URL + "/ip/%s", second.URL + "/ip/%s"}
	t.Cleanup(func() { rdapEndpointTemplates = orig })

	got, err := lookupRDAP(context.Background(), "89.34.96.77")
	if err != nil {
		t.Fatalf("lookup RDAP fallback: %v", err)
	}
	if got.Name != "Example Network" {
		t.Fatalf("network = %q, want Example Network", got.Name)
	}
	if len(got.AbuseContacts) != 1 || got.AbuseContacts[0] != "abuse@example.net" {
		t.Fatalf("abuse contacts = %#v, want abuse@example.net", got.AbuseContacts)
	}
}

func TestLookupRDAPContinuesWhenRegistryHasNoAbuseContact(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"name": "Parent Registry", "entities": []}`))
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{
			"name": "Specific Network",
			"entities": [{
				"roles": ["abuse"],
				"vcardArray": ["vcard", [
					["fn", {}, "text", "Abuse Desk"],
					["email", {}, "text", "abuse@specific.example"]
				]]
			}]
		}`))
	}))
	defer second.Close()

	orig := rdapEndpointTemplates
	rdapEndpointTemplates = []string{first.URL + "/ip/%s", second.URL + "/ip/%s"}
	t.Cleanup(func() { rdapEndpointTemplates = orig })

	got, err := lookupRDAP(context.Background(), "175.110.122.89")
	if err != nil {
		t.Fatalf("lookup RDAP no-contact fallback: %v", err)
	}
	if got.Name != "Specific Network" {
		t.Fatalf("network = %q, want Specific Network", got.Name)
	}
	if len(got.AbuseContacts) != 1 || got.AbuseContacts[0] != "abuse@specific.example" {
		t.Fatalf("abuse contacts = %#v, want abuse@specific.example", got.AbuseContacts)
	}
}

func TestBuildAbuseReportBodySummarizesEvidenceAttachment(t *testing.T) {
	from := "phish@example.net"
	subject := "Click https://credential.example/login"
	threat := "PHISHING"
	entry := &Entry{
		ID:          uuid.New(),
		FromAddr:    &from,
		ToAddr:      "victim@example.com",
		Subject:     &subject,
		ThreatClass: &threat,
		ReceivedAt:  time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC),
	}
	body := buildAbuseReportBody(entry, &SourceIPReport{IP: "203.0.113.5", NetworkName: "Example Net"})
	if strings.Contains(body, "https://credential.example/login") {
		t.Fatalf("report body included phishing URL: %q", body)
	}
	for _, want := range []string{"Source IP: 203.0.113.5", "SMTP sender: phish@example.net", "message/rfc822 evidence attachment"} {
		if !strings.Contains(body, want) {
			t.Fatalf("report body missing %q: %q", want, body)
		}
	}
}

func TestWorldstreamAbuseProviderDetection(t *testing.T) {
	tests := []struct {
		name string
		in   *rdapLookup
		want bool
	}{
		{name: "network name", in: &rdapLookup{Name: "Worldstream IPv4"}, want: true},
		{name: "abuse contact", in: &rdapLookup{Name: "Customer Net", AbuseContacts: []string{"abuse@worldstream.com"}}, want: true},
		{name: "other provider", in: &rdapLookup{Name: "Example Net", AbuseContacts: []string{"abuse@example.net"}}, want: false},
		{name: "nil", in: nil, want: false},
	}
	for _, tt := range tests {
		if got := isWorldstreamAbuseProvider(tt.in); got != tt.want {
			t.Fatalf("%s: isWorldstreamAbuseProvider() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestWorldstreamAdditionalInfoMatchesFormFields(t *testing.T) {
	sourceIP := "203.0.113.5"
	from := "spam@example.net"
	entry := &Entry{
		ID:         uuid.New(),
		FromAddr:   &from,
		ToAddr:     "victim@example.com",
		ClientIP:   &sourceIP,
		ReceivedAt: time.Date(2026, 7, 1, 15, 4, 0, 0, time.UTC),
	}
	report := &SourceIPReport{
		IP:            sourceIP,
		NetworkName:   "Worldstream",
		ReportSubject: "Spam email from 203.0.113.5",
	}
	report.ReportBody = buildAbuseReportBody(entry, report)
	info := buildWorldstreamAdditionalInfo(entry, report)
	for _, want := range []string{
		"Abuse type: Spam",
		"Abuse subtype: Sending email spam",
		"IP address of reported content: 203.0.113.5",
		"Date of incident: 2026-07-01T15:04:00Z",
		"SMTP sender: spam@example.net",
	} {
		if !strings.Contains(info, want) {
			t.Fatalf("Worldstream additional info missing %q:\n%s", want, info)
		}
	}
}

func TestBuildAbuseReportMessageAttachesOriginalMessage(t *testing.T) {
	from := "phish@example.net"
	entry := &Entry{
		ID:         uuid.New(),
		FromAddr:   &from,
		ToAddr:     "victim@example.com",
		ReceivedAt: time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC),
	}
	original := []byte("From: phish@example.net\r\nSubject: Evidence\r\n\r\nbody")
	raw := string(buildAbuseReportMessage(
		"SentinelMail <no-reply@example.com>",
		[]string{"abuse@example.net"},
		"Phishing email from 203.0.113.5",
		"Report body",
		entry,
		&SourceIPReport{IP: "203.0.113.5"},
		original,
		true,
	))
	for _, want := range []string{
		"Content-Type: multipart/report;",
		"Content-Type: message/feedback-report",
		"Content-Type: message/rfc822",
		"Content-Disposition: attachment; filename=\"original-message.eml\"",
		"From: phish@example.net\r\nSubject: Evidence",
		"Feedback-Type: abuse",
		"Source-IP: 203.0.113.5",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("abuse report missing %q:\n%s", want, raw)
		}
	}
}

func TestBuildAbuseReportMessageAttachesSynthesizedEvidence(t *testing.T) {
	from := "phish@example.net"
	subject := "Evidence unavailable"
	sourceIP := "203.0.113.9"
	threat := "PHISHING"
	entry := &Entry{
		ID:          uuid.New(),
		FromAddr:    &from,
		ToAddr:      "victim@example.com",
		Subject:     &subject,
		ClientIP:    &sourceIP,
		ReceivedAt:  time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC),
		ThreatClass: &threat,
	}
	evidence := synthesizedEvidenceMessage(entry)
	raw := string(buildAbuseReportMessage(
		"SentinelMail <no-reply@example.com>",
		[]string{"abuse@example.net"},
		"Phishing email from 203.0.113.9",
		"Report body",
		entry,
		&SourceIPReport{IP: "203.0.113.9"},
		evidence,
		false,
	))
	for _, want := range []string{
		"Content-Type: message/rfc822",
		"Content-Disposition: attachment; filename=\"sentinelmail-evidence.eml\"",
		"X-SentinelMail-Evidence-ID: " + entry.ID.String(),
		"X-SentinelMail-Source-IP: 203.0.113.9",
		"original raw message was not available",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("abuse report missing %q:\n%s", want, raw)
		}
	}
}

func TestParseReportableSourceIPAcceptsCIDR(t *testing.T) {
	ip, err := parseReportableSourceIP("69.171.232.151/32")
	if err != nil {
		t.Fatalf("parse CIDR source IP: %v", err)
	}
	if got := ip.String(); got != "69.171.232.151" {
		t.Fatalf("ip = %q, want 69.171.232.151", got)
	}
}

func TestParseReportableSourceIPAcceptsWrappedCIDR(t *testing.T) {
	ip, err := parseReportableSourceIP("192.174.88.25 2/32")
	if err != nil {
		t.Fatalf("parse wrapped CIDR source IP: %v", err)
	}
	if got := ip.String(); got != "192.174.88.252" {
		t.Fatalf("ip = %q, want 192.174.88.252", got)
	}
}

func TestNormalizedSenderAddress(t *testing.T) {
	from := "SendGrid <NoReply@Example.NET>"
	got, err := normalizedSenderAddress(&from)
	if err != nil {
		t.Fatalf("normalize sender: %v", err)
	}
	if got != "noreply@example.net" {
		t.Fatalf("sender = %q, want noreply@example.net", got)
	}
}

func TestQuarantineNotSpamVerdictMapsToCleanThreatClass(t *testing.T) {
	if got := quarantineThreatClass("not_spam"); got != "NOT_SPAM" {
		t.Fatalf("quarantineThreatClass(not_spam) = %q, want NOT_SPAM", got)
	}
	threat := "NOT_SPAM"
	if got := currentEntryVerdict(&Entry{ThreatClass: &threat}); got != "not_spam" {
		t.Fatalf("currentEntryVerdict(NOT_SPAM) = %q, want not_spam", got)
	}
}

func TestUsePlainInternalRelay(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{host: "postfix", want: true},
		{host: "postfix.", want: true},
		{host: "localhost", want: true},
		{host: "127.0.0.1", want: true},
		{host: "::1", want: true},
		{host: "172.18.0.2", want: true},
		{host: "10.1.2.3", want: true},
		{host: "169.254.1.2", want: true},
		{host: "mail.example.com", want: false},
		{host: "8.8.8.8", want: false},
		{host: "", want: false},
	}
	for _, tt := range tests {
		if got := usePlainInternalRelay(tt.host); got != tt.want {
			t.Fatalf("usePlainInternalRelay(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestSendRelayMailUsesPlainSMTPForInternalRelay(t *testing.T) {
	server := startStartTLSAdvertisingSMTPTestServer(t)
	defer server.Close()

	err := sendRelayMail(
		"127.0.0.1",
		fmt.Sprintf("%d", server.Port),
		"sender@example.com",
		[]string{"abuse@example.net"},
		[]byte("Subject: test\r\n\r\nbody\r\n"),
	)
	if err != nil {
		t.Fatalf("send relay mail: %v", err)
	}
	select {
	case got := <-server.Messages:
		if !strings.Contains(got, "Subject: test") || !strings.Contains(got, "body") {
			t.Fatalf("message body mismatch: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("smtp test server did not receive message")
	}
	for command := range server.Commands {
		if strings.HasPrefix(strings.ToUpper(command), "STARTTLS") {
			t.Fatalf("internal relay attempted STARTTLS: commands=%#v", command)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}

type smtpTestServer struct {
	Port     int
	Messages chan string
	close    func()
}

func (s smtpTestServer) Close() { s.close() }

func startSMTPTestServer(t *testing.T) smtpTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen smtp: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("smtp addr: %v", err)
	}
	portNum := 0
	if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil {
		t.Fatalf("smtp port parse: %v", err)
	}
	messages := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writeLine := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
		writeLine("220 test smtp")
		inData := false
		var data strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					messages <- data.String()
					writeLine("250 queued")
					inData = false
					continue
				}
				data.WriteString(line)
				data.WriteString("\r\n")
				continue
			}
			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, "HELO"), strings.HasPrefix(upper, "EHLO"):
				writeLine("250 localhost")
			case strings.HasPrefix(upper, "MAIL FROM:"):
				writeLine("250 sender ok")
			case strings.HasPrefix(upper, "RCPT TO:"):
				writeLine("250 recipient ok")
			case upper == "DATA":
				writeLine("354 end with dot")
				inData = true
			case upper == "QUIT":
				writeLine("221 bye")
				return
			default:
				writeLine("250 ok")
			}
		}
	}()
	return smtpTestServer{
		Port:     portNum,
		Messages: messages,
		close: func() {
			_ = ln.Close()
			<-done
		},
	}
}

type startTLSTestServer struct {
	Port     int
	Messages chan string
	Commands chan string
	close    func()
}

func (s startTLSTestServer) Close() { s.close() }

func startStartTLSAdvertisingSMTPTestServer(t *testing.T) startTLSTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen smtp: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("smtp addr: %v", err)
	}
	portNum := 0
	if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil {
		t.Fatalf("smtp port parse: %v", err)
	}
	messages := make(chan string, 1)
	commands := make(chan string, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(commands)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writeLine := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
		writeLine("220 test smtp")
		inData := false
		var data strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			commands <- line
			if inData {
				if line == "." {
					messages <- data.String()
					writeLine("250 queued")
					inData = false
					continue
				}
				data.WriteString(line)
				data.WriteString("\r\n")
				continue
			}
			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, "HELO"):
				writeLine("250 localhost")
			case strings.HasPrefix(upper, "EHLO"):
				writeLine("250-localhost")
				writeLine("250-STARTTLS")
				writeLine("250 OK")
			case strings.HasPrefix(upper, "STARTTLS"):
				writeLine("454 TLS unavailable in test")
				return
			case strings.HasPrefix(upper, "MAIL FROM:"):
				writeLine("250 sender ok")
			case strings.HasPrefix(upper, "RCPT TO:"):
				writeLine("250 recipient ok")
			case upper == "DATA":
				writeLine("354 end with dot")
				inData = true
			case upper == "QUIT":
				writeLine("221 bye")
				return
			default:
				writeLine("250 ok")
			}
		}
	}()
	return startTLSTestServer{
		Port:     portNum,
		Messages: messages,
		Commands: commands,
		close: func() {
			_ = ln.Close()
			<-done
		},
	}
}
