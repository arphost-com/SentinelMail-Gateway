import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, ListResponse } from "../api/client";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { HorizontalBars, StatTile } from "../components/ui/Charts";
import { Field } from "../components/ui/Field";
import { HelpTooltip } from "../components/ui/HelpTooltip";

interface Domain {
  id: string;
  name: string;
  is_active: boolean;
}

interface VerificationCheck {
  key: string;
  label: string;
  status: "pass" | "warn" | "fail" | "unknown";
  detail: string;
}

interface Verification {
  domain: Domain;
  expected_mx: string;
  dns: {
    mx: string[];
    matches: boolean;
    error?: string;
    checked_at: string;
  };
  gateways: {
    total: number;
    active: number;
  };
  mail: {
    last_24h: number;
    newest_at: string | null;
    disposition: Record<string, number>;
  };
  checks: VerificationCheck[];
}

const STATUS_CLASS: Record<VerificationCheck["status"], string> = {
  pass: "border-success/50 bg-success/10 text-success",
  warn: "border-warning/50 bg-warning/10 text-warning",
  fail: "border-danger/50 bg-danger/10 text-danger",
  unknown: "border-border bg-muted text-fg",
};

export function DomainVerificationPage() {
  const [params, setParams] = useSearchParams();
  const selected = params.get("domain") ?? "";
  const [domainID, setDomainID] = useState(selected);

  const domains = useQuery({
    queryKey: ["domains", "verification"],
    queryFn: () => api.get<ListResponse<Domain>>("/domains?limit=500"),
  });

  useEffect(() => {
    if (domainID || !domains.data?.items.length) return;
    const first = domains.data.items[0].id;
    setDomainID(first);
    setParams({ domain: first }, { replace: true });
  }, [domainID, domains.data?.items, setParams]);

  const verification = useQuery({
    queryKey: ["domain-verification", domainID],
    queryFn: () => api.get<Verification>(`/domains/${domainID}/verification`),
    enabled: Boolean(domainID),
    refetchInterval: 30_000,
  });

  function choose(id: string) {
    setDomainID(id);
    setParams(id ? { domain: id } : {}, { replace: true });
  }

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-1">Domain verification</h1>
      <p className="text-sm text-subtle mb-4">
        DNS, downstream gateway, and recent observed mail checks for each managed domain.
      </p>

      <Card className="mb-4">
        <CardHeader>
          <CardTitle>Select domain</CardTitle>
        </CardHeader>
        <CardBody>
          <Field label="Domain" help="Choose the managed domain to verify DNS routing, active downstream gateways, and recent observed mail flow.">
            <select
              value={domainID}
              onChange={(e) => choose(e.target.value)}
              className="block w-full max-w-xl rounded border border-border bg-surface px-3 py-2 text-fg"
            >
              <option value="">Select a domain</option>
              {domains.data?.items.map((d) => (
                <option key={d.id} value={d.id}>{d.name}</option>
              ))}
            </select>
          </Field>
        </CardBody>
      </Card>

      {verification.error && (
        <div role="alert" className="text-sm text-danger mb-4">
          {verification.error instanceof Error ? verification.error.message : "Failed to load verification"}
        </div>
      )}

      {verification.isLoading && domainID && <div className="text-sm text-subtle">Loading…</div>}

      {verification.data && (
        <>
          <div className="grid gap-4 grid-cols-1 lg:grid-cols-4 mb-4">
            {verification.data.checks.map((check) => (
              <Card key={check.key}>
                <CardHeader>
                  <CardTitle className="text-base inline-flex items-center gap-2">
                    <span>{check.label}</span>
                    <HelpTooltip text="Pass means this domain check currently matches the expected production setup. Warn or fail means mail may still flow, but the configuration needs review." />
                  </CardTitle>
                </CardHeader>
                <CardBody>
                  <span className={`inline-flex rounded border px-2 py-1 text-xs font-medium uppercase ${STATUS_CLASS[check.status]}`}>
                    {check.status}
                  </span>
                  <p className="text-sm text-subtle mt-3 break-words">{check.detail}</p>
                </CardBody>
              </Card>
            ))}
          </div>

          <div className="grid gap-4 grid-cols-1 lg:grid-cols-3">
            <Card>
              <CardHeader>
                <CardTitle className="inline-flex items-center gap-2">
                  <span>DNS</span>
                  <HelpTooltip text="MX records should point to the SentinelMail gateway host so inbound mail is filtered before it reaches the downstream mail server." />
                </CardTitle>
              </CardHeader>
              <CardBody className="text-sm">
                <dl className="grid grid-cols-3 gap-2">
                  <dt className="text-subtle">Expected MX</dt>
                  <dd className="col-span-2 font-mono text-xs break-all">{verification.data.expected_mx || "not set"}</dd>
                  <dt className="text-subtle">Current MX</dt>
                  <dd className="col-span-2 font-mono text-xs break-all">
                    {verification.data.dns.mx.length ? verification.data.dns.mx.join(", ") : "none"}
                  </dd>
                  <dt className="text-subtle">Checked</dt>
                  <dd className="col-span-2">{new Date(verification.data.dns.checked_at).toLocaleString()}</dd>
                </dl>
              </CardBody>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="inline-flex items-center gap-2">
                  <span>Gateways</span>
                  <HelpTooltip text="Active gateways are downstream delivery targets for accepted or released mail. A domain with no active gateway cannot receive released quarantine mail." />
                </CardTitle>
              </CardHeader>
              <CardBody className="text-sm">
                <StatTile
                  label="Active gateways"
                  value={verification.data.gateways.active}
                  loading={false}
                  tone={verification.data.gateways.active > 0 ? "success" : "danger"}
                  total={Math.max(verification.data.gateways.total, verification.data.gateways.active)}
                  hint={`active of ${verification.data.gateways.total} configured`}
                  showLabel={false}
                />
              </CardBody>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="inline-flex items-center gap-2">
                  <span>Observed mail</span>
                  <HelpTooltip text="Recent observed mail confirms that SentinelMail is seeing traffic for the domain. Zero messages can be normal for quiet domains." />
                </CardTitle>
              </CardHeader>
              <CardBody className="text-sm">
                <StatTile
                  label="Observed mail"
                  value={verification.data.mail.last_24h}
                  loading={false}
                  hint={verification.data.mail.newest_at ? `newest ${new Date(verification.data.mail.newest_at).toLocaleString()}` : "no recent messages"}
                  showLabel={false}
                />
                <div className="mt-4">
                  <HorizontalBars
                    rows={Object.entries(verification.data.mail.disposition).map(([key, count]) => ({ key, count }))}
                    empty="No delivery outcomes in the last 24 hours."
                    label="Observed delivery outcomes"
                    capitalize
                  />
                </div>
              </CardBody>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
