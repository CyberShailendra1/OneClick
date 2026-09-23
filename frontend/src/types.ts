export interface VtResult {
  positives?: number;
  total?: number;
  scan_date?: string;
  permalink?: string;
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  scans?: Record<string, { detected: boolean; result: string | null }>;
  cached?: boolean;
}

export interface Features {
  package_name?: string;
  app_name?: string;
  version_name?: string;
  version_code?: string;
  min_sdk?: string;
  target_sdk?: string;
  num_permissions?: number;
  num_activities?: number;
  num_services?: number;
  num_receivers?: number;
  num_providers?: number;
  requested_permissions?: string[];
  dangerous_permissions?: string[];
  suspicious_apis?: string[];
  has_dex_loader?: boolean;
  has_crypto?: boolean;
}

export interface AdvancedAnalysis {
  hardcoded_ips?: string[];
  hardcoded_urls?: string[];
  exported_components?: {
    activities?: string[];
    services?: string[];
    receivers?: string[];
    providers?: string[];
  };
  native_libraries?: string[];
  detected_sdks?: string[];
  obfuscation_indicators?: string[];
}

export interface MlResult {
  label: 'Safe' | 'Suspicious' | 'Malicious' | 'Known Threat';
  risk_score: number;
  reasons: string[];
}

export interface ScanResult {
  sha256: string;
  filename?: string;
  known_threat: boolean;
  vt_result?: VtResult | null;
  features?: Features | null;
  advanced?: AdvancedAnalysis | null;
  ml_result?: MlResult | null;
  error?: string | null;
}

export interface HistoryRecord {
  id: number;
  filename: string;
  sha256: string;
  risk_score: number;
  verdict: string;
  vt_positives: number;
  scanned_at: string;
}

export interface UrlScanResult {
  url: string;
  score: number;
  label: 'Safe' | 'Suspicious' | 'Malicious';
  reasons: string[];
  vt?: any;
}

export interface MessageScanResponse {
  urls_found: number;
  results: UrlScanResult[];
}

export interface UrlHistoryRecord {
  id: number;
  url: string;
  verdict: string;
  risk_score: number;
  reasons: string;
  action: string;
  scanned_at: string;
}

export interface InvestigationResult {
  final_url: string;
  redirect_chain: string[];
  external_scripts: string[];
  forms: Array<{ action: string; method: string; inputs: string[] }>;
  has_password_field: boolean;
  has_credit_card_field: boolean;
  has_meta_refresh: boolean;
  notes: string[];
}

export interface RedactResult {
  redacted_text: string;
  codes_found: number;
}

export interface ScamCheckResult {
  is_reported: boolean;
  category: string | null;
  report_count: number;
  note: string | null;
}

export interface BreachResult {
  pwned: boolean;
  count: number;
  error?: string | null;
}

export interface HeaderFinding {
  header: string;
  title: string;
  present: boolean;
  value: string | null;
  importance: 'Critical' | 'High' | 'Medium' | 'Low';
  description: string;
  recommendation: string | null;
}

export interface SecurityHeadersResult {
  url: string;
  status_code?: number;
  score?: number;
  grade?: string;
  present_count?: number;
  missing_count?: number;
  server?: string;
  findings?: HeaderFinding[];
  error?: string;
}

export interface SslCertResult {
  hostname: string;
  valid: boolean;
  days_left?: number;
  expires_on?: string;
  issued_on?: string;
  issuer?: string;
  subject?: string;
  subject_alt_names?: string[];
  tls_version?: string;
  cipher_suite?: string;
  serial_number?: string;
  error?: string;
}

export interface EmailSecurityResult {
  domain: string;
  spoofable: boolean;
  spf: {
    status: string;
    record: string | null;
    strength: string;
  };
  dmarc: {
    status: string;
    record: string | null;
    policy: string;
  };
  has_mx: boolean;
  mx_records: string[];
  vulnerabilities: string[];
}

export interface PortExposureItem {
  port: number;
  service: string;
  state: 'open' | 'closed' | 'filtered';
  description: string;
  risk: 'High' | 'Normal';
}

export interface PortScanResult {
  target?: string;
  resolved_ip?: string;
  open_ports_count?: number;
  ports?: PortExposureItem[];
  error?: string;
}

export interface GenericFileResult {
  filename: string;
  size_bytes: number;
  size_formatted: string;
  hashes: {
    md5: string;
    sha1: string;
    sha256: string;
  };
  verdict: string;
  virustotal?: any;
}

export interface SmartAnalyzeResult {
  type: 'phone' | 'upi' | 'url' | 'message';
  level: 'safe' | 'caution' | 'danger';
  title: string;
  summary: string;
  actions: string[];
  details: {
    redacted_preview?: string;
    threats_detected?: string[];
    [key: string]: any;
  };
}



