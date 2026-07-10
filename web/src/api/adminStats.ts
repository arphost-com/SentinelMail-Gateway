export interface AdminStats {
  window: string;
  since: string;
  msps: MSPStatsRow[];
  orgs: OrgStatsRow[];
  users: UserStatsRow[];
}

export interface MSPStatsRow {
  id: string;
  name: string;
  slug: string;
  child_orgs: number;
  active_users: number;
  domains: number;
  processed: number;
  quarantined: number;
  rejected: number;
  phishing_reports: number;
}

export interface OrgStatsRow {
  id: string;
  name: string;
  slug: string;
  parent_id?: string;
  is_active: boolean;
  active_users: number;
  domains: number;
  processed: number;
  quarantined: number;
  rejected: number;
  phishing_reports: number;
}

export interface UserStatsRow {
  id: string;
  organization_id: string;
  email: string;
  display_name?: string;
  role: string;
  is_active: boolean;
  last_login_at?: string;
  processed: number;
  quarantined: number;
  reported_threats: number;
}

export function adminWindowLabel(windowValue: string) {
  switch (windowValue) {
    case "24h":
      return "last 24 hours";
    case "30d":
      return "last 30 days";
    default:
      return "last 7 days";
  }
}

