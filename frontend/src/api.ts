import {
  ScanResult,
  HistoryRecord,
  UrlScanResult,
  MessageScanResponse,
  UrlHistoryRecord,
  InvestigationResult,
  RedactResult,
  ScamCheckResult,
  BreachResult,
  SecurityHeadersResult,
  SslCertResult,
  EmailSecurityResult,
  PortScanResult,
  GenericFileResult,
} from './types';

const API_BASE = ''; // uses Vite proxy in dev, or same host in prod

export async function checkHealth(): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function scanApk(
  file: File,
  vtApiKey?: string,
  advanced: boolean = true
): Promise<ScanResult> {
  const formData = new FormData();
  formData.append('file', file);

  const params = new URLSearchParams();
  if (vtApiKey) params.append('vt_api_key', vtApiKey);
  params.append('advanced', String(advanced));

  const res = await fetch(`${API_BASE}/scan?${params.toString()}`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({ detail: 'Scan request failed' }));
    throw new Error(errorData.detail || `Scan failed with status ${res.status}`);
  }
  return res.json();
}

export async function downloadReport(
  file: File,
  format: 'pdf' | 'json',
  vtApiKey?: string
): Promise<void> {
  const formData = new FormData();
  formData.append('file', file);

  const params = new URLSearchParams();
  if (vtApiKey) params.append('vt_api_key', vtApiKey);
  params.append('format', format);

  const res = await fetch(`${API_BASE}/scan/report?${params.toString()}`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Report generation failed' }));
    throw new Error(err.detail || 'Download failed');
  }

  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `oneclick_report_${file.name.replace(/\.apk$/i, '')}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export async function getHistory(limit: number = 50): Promise<HistoryRecord[]> {
  const res = await fetch(`${API_BASE}/history?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to load history');
  return res.json();
}

export async function clearHistory(): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE}/history`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to clear history');
  return res.json();
}

export async function scanUrl(url: string, vtApiKey?: string): Promise<UrlScanResult> {
  const res = await fetch(`${API_BASE}/scan-url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, vt_api_key: vtApiKey || null }),
  });
  if (!res.ok) throw new Error('Failed to scan URL');
  return res.json();
}

export async function investigateUrl(url: string): Promise<InvestigationResult> {
  const res = await fetch(`${API_BASE}/investigate-url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error('Failed to investigate URL');
  return res.json();
}

export async function scanMessage(text: string, vtApiKey?: string): Promise<MessageScanResponse> {
  const res = await fetch(`${API_BASE}/scan-message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, vt_api_key: vtApiKey || null }),
  });
  if (!res.ok) throw new Error('Failed to scan message');
  return res.json();
}

export async function getUrlHistory(limit: number = 50): Promise<UrlHistoryRecord[]> {
  const res = await fetch(`${API_BASE}/url-history?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to load URL history');
  return res.json();
}

export async function setUrlAction(
  rowId: number,
  action: 'dismissed' | 'deleted_by_user' | 'none'
): Promise<{ status: string; id: number; action: string }> {
  const res = await fetch(`${API_BASE}/url-history/${rowId}/action?action=${action}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to update URL action');
  return res.json();
}

export async function clearUrlHistory(): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE}/url-history`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to clear URL history');
  return res.json();
}

export async function redactMessage(text: string): Promise<RedactResult> {
  const res = await fetch(`${API_BASE}/redact-message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) throw new Error('Failed to redact message');
  return res.json();
}

export async function checkPhone(phone: string): Promise<ScamCheckResult> {
  const res = await fetch(`${API_BASE}/scam-lookup/phone`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phone }),
  });
  if (!res.ok) throw new Error('Failed to check phone number');
  return res.json();
}

export async function checkUpi(upiId: string): Promise<ScamCheckResult> {
  const res = await fetch(`${API_BASE}/scam-lookup/upi`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ upi_id: upiId }),
  });
  if (!res.ok) throw new Error('Failed to check UPI ID');
  return res.json();
}

export async function addScamReport(
  type: string,
  value: string,
  category: string,
  note?: string
): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE}/scam-lookup/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type, value, category, note: note || null }),
  });
  if (!res.ok) throw new Error('Failed to submit report');
  return res.json();
}

export async function checkPasswordBreach(password: string): Promise<BreachResult> {
  const res = await fetch(`${API_BASE}/breach/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  if (!res.ok) throw new Error('Failed to check password');
  return res.json();
}

export async function checkSecurityHeaders(url: string): Promise<SecurityHeadersResult> {
  const res = await fetch(`${API_BASE}/tools/security-headers`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error('Headers check failed');
  return res.json();
}

export async function inspectSslCert(host: string): Promise<SslCertResult> {
  const res = await fetch(`${API_BASE}/tools/ssl-cert`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host }),
  });
  if (!res.ok) throw new Error('SSL cert inspection failed');
  return res.json();
}

export async function checkEmailSecurity(domain: string): Promise<EmailSecurityResult> {
  const res = await fetch(`${API_BASE}/tools/email-security`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain }),
  });
  if (!res.ok) throw new Error('Email security check failed');
  return res.json();
}

export async function scanPortExposure(host: string): Promise<PortScanResult> {
  const res = await fetch(`${API_BASE}/tools/port-scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host }),
  });
  if (!res.ok) throw new Error('Port scan failed');
  return res.json();
}

export async function scanGenericFile(file: File, vtApiKey?: string): Promise<GenericFileResult> {
  const formData = new FormData();
  formData.append('file', file);
  const params = new URLSearchParams();
  if (vtApiKey) params.append('vt_api_key', vtApiKey);

  const res = await fetch(`${API_BASE}/tools/scan-file?${params.toString()}`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) throw new Error('File scan failed');
  return res.json();
}


