# Campaign grouping and flood protection

SentinelMail groups repeated mail into daily tenant-scoped campaigns using a
stable fingerprint of the sender, sender domain, recipient, normalized subject,
and normalized message content. Message IDs, source IPs, tracking URLs, and
changing numeric tokens do not split otherwise identical copies into separate
investigations.

For high-confidence spam and phishing, the first copy remains the representative
quarantine record with its original message. Later copies are still recorded in
the mail log and campaign source-IP counts, but SentinelMail does not create
duplicate quarantine blobs, async scans, or phishing-alert email. The quarantine
page shows the total copies, suppressed copies, unique source IPs, and first/last
seen window.

Organization policy controls define the copy threshold and the action:

- **Aggregate:** continue accepting and grouping blocked copies in quarantine.
- **Reject:** return an SMTP rejection after the threshold.
- **Discard:** accept and silently discard after the threshold, avoiding
  backscatter to forged senders.

Authentication-only holds and challenge-response mail are excluded from
high-confidence flood suppression. A user phishing or malware report also marks
unreviewed mailbox copies in the same recipient campaign. Abuse-report previews
include campaign totals and up to 100 observed source addresses so the operator
can report the coordinated activity without exposing every duplicate message.

The regression suite includes the observed Trust Card flood shape: 1,718 unique
messages from 1,101 source IPs must produce one stable campaign fingerprint and
one representative quarantine investigation.
