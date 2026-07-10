# SentinelMail Customer Quick Start

This guide is for customers receiving a SentinelMail Gateway, either onsite on your own server or hosted by an MSP/provider. It covers the handoff steps needed to start filtering mail safely.

## What SentinelMail Does

SentinelMail sits in front of your real mail server. Internet senders deliver mail to SentinelMail first. SentinelMail checks authentication, spam score, malware signals, phishing indicators, sender reputation, and customer policy, then either delivers the message to your downstream mail server or holds it in quarantine for review.

## Before You Start

Have these details ready:

- Your protected domain names, such as `example.com`.
- The downstream mail server hostname or IP that should receive clean mail.
- A public hostname for the gateway, such as `spam01.example.com` or the hostname provided by your MSP.
- Access to update DNS records for each protected domain.
- The admin sign-in URL and first admin account from your installer or MSP.

## Onsite Install Checklist

Use this checklist when SentinelMail runs on a customer-owned server.

1. Confirm the server has inbound ports `25`, `80`, and `443` open from the internet.
2. Confirm the server can reach the downstream mail server on SMTP port `25` or the port your mail system requires.
3. Point the gateway hostname DNS `A` record at the server's public IP.
4. Sign in to SentinelMail as the first admin and enable two-factor authentication.
5. Add each protected domain under **Domains**.
6. Add one or more downstream gateways under **Gateways** for each protected domain.
7. Update each domain's MX record to point to the SentinelMail gateway hostname.
8. Send a test message from an outside mailbox and verify it appears in **Mail logs**.
9. Review **Quarantine** for held messages and release or delete as needed.

## MSP-Hosted Customer Checklist

Use this checklist when your provider hosts SentinelMail for you.

1. Confirm the provider created your organization and admin account.
2. Sign in to the provided URL and enable two-factor authentication.
3. Confirm your protected domains are listed under **Domains**.
4. Confirm your downstream gateway details are correct under **Gateways**.
5. Update your DNS MX records to the gateway hostname supplied by the provider.
6. Send test mail from outside your organization.
7. Review **Mail logs** and **Quarantine** with your provider before fully cutting over.

## Recommended DNS Records

Your installer or provider will give exact values. In most deployments:

- `MX` points the protected domain to the SentinelMail gateway hostname.
- `SPF` should continue to authorize the systems that send mail for your domain.
- `DKIM` remains configured at your outbound mail provider.
- `DMARC` should stay enabled so SentinelMail can identify spoofed mail accurately.

Do not delete existing SPF, DKIM, or DMARC records during cutover unless your mail administrator tells you to.

## First Admin Tasks

After sign-in:

1. Enable two-factor authentication in **Settings -> Account**.
2. Create named admin accounts for people who will manage quarantine, users, domains, or policies.
3. Create end-user accounts for people who need self-service quarantine access.
4. Review policy thresholds under **Policies** before changing defaults.
5. Confirm alerts and background-task notifications in **Settings -> Account**.

## End-User Tasks

End users can:

- Sign in and enable two-factor authentication.
- Review only quarantine messages addressed to them.
- Release legitimate mail.
- Delete unwanted messages.
- Block spam senders or sender domains from quarantine.
- Review their own mail log and audit activity.

## When Something Looks Wrong

Check in this order:

1. **Mail logs** - confirms whether SentinelMail saw the message and what action it took.
2. **Quarantine** - shows held mail that can be released or deleted.
3. **SMTP events** - shows rejects, TLS failures, and delivery deferrals that happened before a normal mail log was created.
4. **Reports** - summarizes mail flow and threat trends for the selected time window.

If mail is missing and there is no mail log, ask your installer or provider to check DNS, firewall access, and SMTP events.

## Support Handoff

Keep these details available for support:

- SentinelMail URL.
- Gateway hostname.
- Protected domain.
- Sender, recipient, subject, and approximate time of the test message.
- Screenshot or text from the matching **Mail logs**, **Quarantine**, or **SMTP events** row.

Never forward suspected phishing links to support unless they ask for the quarantined message metadata. Use SentinelMail's quarantine and report actions instead.
