dns {
  # Rspamd does not use libc's resolver. Send reputation/authentication DNS
  # through our full recursive Unbound service so DNSBL providers see this
  # gateway's own query source instead of a blocked shared forwarder.
  # Docker DNS remains fallback-only to preserve mail flow if Unbound fails.
  nameserver = "master-slave:unbound:5353,127.0.0.11:53";
  timeout = 1s;
  retransmits = 2;
  sockets = 16;
}
