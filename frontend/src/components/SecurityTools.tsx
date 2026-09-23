import React, { useState, useRef } from 'react';
import {
  Wrench, Globe, Shield, Mail, Lock, Server, FileSearch,
  CheckCircle, AlertTriangle, XCircle, Info, ExternalLink, RefreshCw, Upload, Copy, Check
} from 'lucide-react';
import {
  checkSecurityHeaders,
  inspectSslCert,
  checkEmailSecurity,
  scanPortExposure,
  scanGenericFile,
} from '../api';
import {
  SecurityHeadersResult,
  SslCertResult,
  EmailSecurityResult,
  PortScanResult,
  GenericFileResult,
} from '../types';

interface SecurityToolsProps {
  vtApiKey: string;
}

export const SecurityTools: React.FC<SecurityToolsProps> = ({ vtApiKey }) => {
  const [activeTool, setActiveTool] = useState<'headers' | 'email' | 'file' | 'password' | 'ports'>('headers');

  // 1. Web Headers & SSL state
  const [webTarget, setWebTarget] = useState<string>('');
  const [headersLoading, setHeadersLoading] = useState<boolean>(false);
  const [headersResult, setHeadersResult] = useState<SecurityHeadersResult | null>(null);
  const [sslResult, setSslResult] = useState<SslCertResult | null>(null);

  // 2. Email Spoof state
  const [emailDomain, setEmailDomain] = useState<string>('');
  const [emailLoading, setEmailLoading] = useState<boolean>(false);
  const [emailResult, setEmailResult] = useState<EmailSecurityResult | null>(null);

  // 3. File Hash & VT state
  const [genericFile, setGenericFile] = useState<File | null>(null);
  const [fileLoading, setFileLoading] = useState<boolean>(false);
  const [fileResult, setFileResult] = useState<GenericFileResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // 4. Password Entropy state
  const [testPassword, setTestPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);

  // 5. Port Scan state
  const [portTarget, setPortTarget] = useState<string>('');
  const [portLoading, setPortLoading] = useState<boolean>(false);
  const [portResult, setPortResult] = useState<PortScanResult | null>(null);

  // Handlers
  const handleCheckWeb = async () => {
    if (!webTarget.trim()) return;
    setHeadersLoading(true);
    setHeadersResult(null);
    setSslResult(null);

    try {
      const [hRes, sRes] = await Promise.allSettled([
        checkSecurityHeaders(webTarget.trim()),
        inspectSslCert(webTarget.trim()),
      ]);

      if (hRes.status === 'fulfilled') setHeadersResult(hRes.value);
      if (sRes.status === 'fulfilled') setSslResult(sRes.value);
    } finally {
      setHeadersLoading(false);
    }
  };

  const handleCheckEmail = async () => {
    if (!emailDomain.trim()) return;
    setEmailLoading(true);
    setEmailResult(null);
    try {
      const res = await checkEmailSecurity(emailDomain.trim());
      setEmailResult(res);
    } catch (err: any) {
      alert(`Email check failed: ${err.message}`);
    } finally {
      setEmailLoading(false);
    }
  };

  const handleScanFile = async (selectedFile?: File) => {
    const f = selectedFile || genericFile;
    if (!f) return;
    setFileLoading(true);
    setFileResult(null);
    try {
      const res = await scanGenericFile(f, vtApiKey);
      setFileResult(res);
    } catch (err: any) {
      alert(`File scan failed: ${err.message}`);
    } finally {
      setFileLoading(false);
    }
  };

  const handleCheckPorts = async () => {
    if (!portTarget.trim()) return;
    setPortLoading(true);
    setPortResult(null);
    try {
      const res = await scanPortExposure(portTarget.trim());
      setPortResult(res);
    } catch (err: any) {
      alert(`Port scan failed: ${err.message}`);
    } finally {
      setPortLoading(false);
    }
  };

  // Password Entropy Calculator (Offline client-side)
  const calculateEntropy = (pwd: string) => {
    if (!pwd) return { entropy: 0, pool: 0, crackTime: '0 seconds', rating: 'None', color: 'var(--text-muted)' };
    let pool = 0;
    if (/[a-z]/.test(pwd)) pool += 26;
    if (/[A-Z]/.test(pwd)) pool += 26;
    if (/[0-9]/.test(pwd)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) pool += 33;

    const entropy = Math.round(pwd.length * Math.log2(pool || 1));
    const combinations = Math.pow(pool || 1, pwd.length);
    const guessesPerSec = 1e11; // 100 billion/sec (fast GPU cluster)
    const seconds = combinations / (2 * guessesPerSec);

    let crackTime = 'Instantly';
    if (seconds > 31536000 * 1000) crackTime = `${(seconds / (31536000 * 1000)).toExponential(1)} millennia`;
    else if (seconds > 31536000) crackTime = `${Math.round(seconds / 31536000)} years`;
    else if (seconds > 86400) crackTime = `${Math.round(seconds / 86400)} days`;
    else if (seconds > 3600) crackTime = `${Math.round(seconds / 3600)} hours`;
    else if (seconds > 60) crackTime = `${Math.round(seconds / 60)} minutes`;
    else if (seconds > 1) crackTime = `${Math.round(seconds)} seconds`;

    let rating = 'Very Weak';
    let color = 'var(--red)';
    if (entropy >= 80) {
      rating = 'Very Strong';
      color = 'var(--green)';
    } else if (entropy >= 60) {
      rating = 'Strong';
      color = 'var(--teal)';
    } else if (entropy >= 40) {
      rating = 'Moderate';
      color = 'var(--amber)';
    }

    return { entropy, pool, crackTime, rating, color };
  };

  const pwdInfo = calculateEntropy(testPassword);

  const tools = [
    { id: 'headers', label: 'Web Headers & SSL', icon: Globe },
    { id: 'email', label: 'Email Spoof (SPF/DMARC)', icon: Mail },
    { id: 'file', label: 'Universal File Scanner', icon: FileSearch },
    { id: 'password', label: 'Password Strength', icon: Lock },
    { id: 'ports', label: 'Port Exposure', icon: Server },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Banner with Sub-Nav */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px', flexWrap: 'wrap', gap: '14px' }}>
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Wrench size={22} color="var(--teal)" /> Cybersecurity Assessment Tools
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '13.5px' }}>
              Essential baseline security checks for web domains, email spoofing, open ports, and file reputation.
            </p>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {tools.map((t) => {
              const Icon = t.icon;
              const active = activeTool === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => setActiveTool(t.id as any)}
                  className={`btn ${active ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ fontSize: '13px', padding: '7px 14px' }}
                >
                  <Icon size={15} />
                  <span>{t.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* =========================================================================
          Tool 1: Web Security Headers & SSL Inspector
         ========================================================================= */}
      {activeTool === 'headers' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="card">
            <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Globe size={18} color="var(--cyan)" /> HTTP Security Headers & SSL/TLS Audit
            </h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '16px' }}>
              Audit website defense-in-depth headers (HSTS, CSP, X-Frame-Options) and live TLS encryption certificate validity.
            </p>

            <div style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
              <input
                type="text"
                className="input-field"
                placeholder="Enter domain or URL (e.g. https://github.com or example.com)"
                value={webTarget}
                onChange={(e) => setWebTarget(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleCheckWeb()}
              />
              <button className="btn btn-primary" onClick={handleCheckWeb} disabled={headersLoading || !webTarget.trim()}>
                {headersLoading ? 'Analyzing...' : 'Audit Target'}
              </button>
            </div>

            {/* Results Grid */}
            {(headersResult || sslResult) && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                {/* Header Score & SSL Summary */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
                  {headersResult && !headersResult.error && (
                    <div style={{ background: 'var(--bg-card-alt)', borderRadius: '10px', padding: '18px', border: '1px solid var(--border)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Security Headers Rating</div>
                          <div style={{ fontSize: '32px', fontWeight: 800, color: headersResult.grade === 'A+' || headersResult.grade === 'A' ? 'var(--green)' : headersResult.grade === 'B' ? 'var(--amber)' : 'var(--red)' }}>
                            Grade {headersResult.grade}
                          </div>
                        </div>
                        <div style={{ textAlign: 'right' }}>
                          <span style={{ fontSize: '20px', fontWeight: 700 }}>{headersResult.score}%</span>
                          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                            {headersResult.present_count} / {(headersResult.present_count || 0) + (headersResult.missing_count || 0)} Headers Set
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {sslResult && (
                    <div style={{ background: 'var(--bg-card-alt)', borderRadius: '10px', padding: '18px', border: '1px solid var(--border)' }}>
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>SSL/TLS Certificate Status</div>
                      {sslResult.valid ? (
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--green)', fontWeight: 700, fontSize: '16px' }}>
                            <CheckCircle size={18} /> Valid Certificate ({sslResult.days_left} days left)
                          </div>
                          <div style={{ fontSize: '12.5px', color: 'var(--text-main)', marginTop: '4px' }}>
                            Issuer: <b>{sslResult.issuer}</b> • TLS: <b>{sslResult.tls_version || '1.3'}</b>
                          </div>
                        </div>
                      ) : (
                        <div style={{ color: 'var(--red)', fontWeight: 700, fontSize: '14px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <XCircle size={18} /> {sslResult.error || 'Invalid or Expired Certificate'}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Headers Findings Table */}
                {headersResult?.findings && (
                  <div className="table-container">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Header</th>
                          <th>Status</th>
                          <th>Importance</th>
                          <th>Value / Recommendation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {headersResult.findings.map((f, i) => (
                          <tr key={i}>
                            <td style={{ fontWeight: 600 }}>{f.header}</td>
                            <td>
                              {f.present ? (
                                <span className="badge badge-safe">Configured</span>
                              ) : (
                                <span className="badge badge-malicious">Missing</span>
                              )}
                            </td>
                            <td>
                              <span style={{
                                color: f.importance === 'Critical' ? 'var(--red)' : f.importance === 'High' ? 'var(--amber)' : 'var(--text-muted)',
                                fontWeight: 700, fontSize: '12px'
                              }}>
                                {f.importance}
                              </span>
                            </td>
                            <td style={{ fontSize: '12.5px' }}>
                              {f.present ? (
                                <code style={{ color: 'var(--teal)' }}>{f.value}</code>
                              ) : (
                                <span style={{ color: 'var(--text-muted)' }}>
                                  Fix: <code>{f.recommendation}</code>
                                </span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* =========================================================================
          Tool 2: Email Spoofing & Phishing (SPF/DMARC)
         ========================================================================= */}
      {activeTool === 'email' && (
        <div className="card">
          <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Mail size={18} color="var(--teal)" /> Domain Email Spoofing & Phishing Defense Checker
          </h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '16px' }}>
            Tests if scammers can forge emails from this domain by inspecting SPF (Sender Policy Framework) and DMARC enforcement policies via DNS-over-HTTPS.
          </p>

          <div style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
            <input
              type="text"
              className="input-field"
              placeholder="e.g. paypal.com, sbi.co.in, or your-company.com"
              value={emailDomain}
              onChange={(e) => setEmailDomain(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCheckEmail()}
            />
            <button className="btn btn-primary" onClick={handleCheckEmail} disabled={emailLoading || !emailDomain.trim()}>
              {emailLoading ? 'Checking Records...' : 'Check Spoof Defense'}
            </button>
          </div>

          {emailResult && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {/* Verdict Banner */}
              <div style={{
                background: emailResult.spoofable ? 'rgba(239, 68, 68, 0.12)' : 'rgba(34, 197, 94, 0.12)',
                border: `1px solid ${emailResult.spoofable ? 'rgba(239, 68, 68, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
                padding: '16px 20px', borderRadius: '10px', display: 'flex', alignItems: 'center', gap: '12px'
              }}>
                {emailResult.spoofable ? <AlertTriangle size={24} color="var(--red)" /> : <CheckCircle size={24} color="var(--green)" />}
                <div>
                  <div style={{ fontSize: '16px', fontWeight: 800, color: emailResult.spoofable ? 'var(--red)' : 'var(--green)' }}>
                    {emailResult.spoofable ? '⚠️ DOMAIN VULNERABLE TO SPOOFING' : '✅ DOMAIN PROTECTED AGAINST FORGERY'}
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--text-main)', marginTop: '2px' }}>
                    {emailResult.spoofable
                      ? 'Adversaries can craft phishing emails that appear to originate directly from this domain.'
                      : 'DMARC and SPF policies are strongly configured to reject unauthorized emails.'}
                  </div>
                </div>
              </div>

              {/* Records Breakdown */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
                <div style={{ background: 'var(--bg-card-alt)', padding: '16px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>SPF Record</div>
                  <div style={{ fontWeight: 700, fontSize: '14px', color: emailResult.spf.status === 'present' ? 'var(--teal)' : 'var(--red)', marginTop: '4px' }}>
                    {emailResult.spf.status === 'present' ? emailResult.spf.strength : 'Missing SPF'}
                  </div>
                  {emailResult.spf.record && (
                    <code style={{ display: 'block', fontSize: '11.5px', marginTop: '8px', wordBreak: 'break-all' }}>
                      {emailResult.spf.record}
                    </code>
                  )}
                </div>

                <div style={{ background: 'var(--bg-card-alt)', padding: '16px', borderRadius: '8px' }}>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>DMARC Policy</div>
                  <div style={{
                    fontWeight: 700, fontSize: '14px',
                    color: emailResult.dmarc.policy === 'reject' || emailResult.dmarc.policy === 'quarantine' ? 'var(--green)' : 'var(--red)',
                    marginTop: '4px'
                  }}>
                    {emailResult.dmarc.status === 'present' ? `Policy: p=${emailResult.dmarc.policy}` : 'Missing DMARC'}
                  </div>
                  {emailResult.dmarc.record && (
                    <code style={{ display: 'block', fontSize: '11.5px', marginTop: '8px', wordBreak: 'break-all' }}>
                      {emailResult.dmarc.record}
                    </code>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          Tool 3: Universal File Threat Scanner (Any File + VirusTotal)
         ========================================================================= */}
      {activeTool === 'file' && (
        <div className="card">
          <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileSearch size={18} color="var(--blue)" /> Universal File Threat Hash Scanner
          </h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '16px' }}>
            Analyze any file (PDF, EXE, DOCX, ZIP, Script, DLL) to compute cryptographic hashes and check VirusTotal global malware reputation.
          </p>

          <div
            className="dropzone"
            onClick={() => fileInputRef.current?.click()}
            style={{ padding: '30px 20px', marginBottom: '16px' }}
          >
            <input
              ref={fileInputRef}
              type="file"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  setGenericFile(e.target.files[0]);
                  handleScanFile(e.target.files[0]);
                }
              }}
              style={{ display: 'none' }}
            />
            <Upload size={32} color="var(--teal)" style={{ margin: '0 auto 8px' }} />
            <div style={{ fontWeight: 700, fontSize: '15px' }}>
              {genericFile ? genericFile.name : 'Select or drop ANY file to inspect'}
            </div>
            <p style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
              {genericFile ? `${(genericFile.size / (1024 * 1024)).toFixed(2)} MB` : 'PDF, Word documents, EXE, ZIP archives, scripts'}
            </p>
          </div>

          {fileLoading && (
            <div style={{ textAlign: 'center', padding: '20px 0', color: 'var(--text-muted)' }}>
              Hashing file and checking threat engines...
            </div>
          )}

          {fileResult && (
            <div style={{ background: 'var(--bg-card-alt)', borderRadius: '10px', padding: '20px', border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
                <div>
                  <h4 style={{ fontSize: '16px', fontWeight: 700 }}>{fileResult.filename}</h4>
                  <span style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>Size: {fileResult.size_formatted}</span>
                </div>
                <span className={`badge ${fileResult.verdict === 'Clean / Undetected' ? 'badge-safe' : fileResult.verdict === 'Suspicious' ? 'badge-suspicious' : 'badge-malicious'}`} style={{ fontSize: '14px', padding: '6px 16px' }}>
                  {fileResult.verdict}
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>SHA-256: </span>
                  <code style={{ color: 'var(--teal)' }}>{fileResult.hashes.sha256}</code>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>MD5: </span>
                  <code>{fileResult.hashes.md5}</code>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>SHA-1: </span>
                  <code>{fileResult.hashes.sha1}</code>
                </div>
              </div>

              {fileResult.virustotal && fileResult.virustotal.found && (
                <div style={{ marginTop: '16px', paddingTop: '14px', borderTop: '1px solid var(--border)' }}>
                  <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>VirusTotal Detections: </span>
                  <b>{fileResult.virustotal.positives} / {fileResult.virustotal.total} engines flagged this sample.</b>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          Tool 4: Password Strength & Entropy Meter (Offline)
         ========================================================================= */}
      {activeTool === 'password' && (
        <div className="card">
          <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Lock size={18} color="var(--amber)" /> Offline Password Entropy & Complexity Meter
          </h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '16px' }}>
            Evaluates mathematical password strength and Shannon entropy locally in your browser. <b>Your password is never transmitted across the network.</b>
          </p>

          <div style={{ position: 'relative', marginBottom: '16px' }}>
            <input
              type={showPassword ? 'text' : 'password'}
              className="input-field"
              placeholder="Type a password to test its brute-force resistance..."
              value={testPassword}
              onChange={(e) => setTestPassword(e.target.value)}
              style={{ fontSize: '15px', paddingRight: '70px' }}
            />
            <button
              onClick={() => setShowPassword(!showPassword)}
              style={{
                position: 'absolute', right: '12px', top: '10px',
                background: 'none', border: 'none', color: 'var(--teal)', cursor: 'pointer', fontSize: '12.5px'
              }}
            >
              {showPassword ? 'Hide' : 'Show'}
            </button>
          </div>

          {testPassword && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', background: 'var(--bg-card-alt)', padding: '18px', borderRadius: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Estimated Crack Time</span>
                  <div style={{ fontSize: '20px', fontWeight: 800, color: pwdInfo.color }}>
                    {pwdInfo.crackTime}
                  </div>
                </div>
                <span className="badge" style={{ background: `${pwdInfo.color}22`, color: pwdInfo.color, fontSize: '13px', padding: '6px 14px' }}>
                  {pwdInfo.rating} ({pwdInfo.entropy} bits)
                </span>
              </div>

              {/* Entropy Bar */}
              <div style={{ height: '8px', background: 'var(--bg-dark)', borderRadius: '4px', overflow: 'hidden' }}>
                <div style={{
                  height: '100%', width: `${Math.min(100, (pwdInfo.entropy / 100) * 100)}%`,
                  background: pwdInfo.color, transition: 'width 0.3s'
                }} />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '10px', fontSize: '12.5px', color: 'var(--text-muted)' }}>
                <div>Length: <b>{testPassword.length} chars</b></div>
                <div>Character Pool: <b>{pwdInfo.pool} choices</b></div>
                <div>Complexity: <b>{pwdInfo.entropy > 60 ? 'High' : 'Low'}</b></div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* =========================================================================
          Tool 5: Open Port & Service Recon (SSRF-Guarded)
         ========================================================================= */}
      {activeTool === 'ports' && (
        <div className="card">
          <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Server size={18} color="var(--red)" /> Network Port Exposure Recon (SSRF Guarded)
          </h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '16px' }}>
            Tests public host IP addresses for critical exposed administrative ports (SSH, FTP, Telnet, RDP, MySQL). Private IP targets are strictly blocked.
          </p>

          <div style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
            <input
              type="text"
              className="input-field"
              placeholder="e.g. scanme.nmap.org or your-public-domain.com"
              value={portTarget}
              onChange={(e) => setPortTarget(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCheckPorts()}
            />
            <button className="btn btn-primary" onClick={handleCheckPorts} disabled={portLoading || !portTarget.trim()}>
              {portLoading ? 'Probing Ports...' : 'Scan Ports'}
            </button>
          </div>

          {portResult && (
            <div>
              {portResult.error ? (
                <div style={{ color: 'var(--red)', background: 'rgba(239, 68, 68, 0.1)', padding: '12px', borderRadius: '8px' }}>
                  {portResult.error}
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  <div style={{ fontSize: '13.5px', color: 'var(--text-muted)' }}>
                    Resolved IP: <b>{portResult.resolved_ip}</b> • Open Ports Found: <b>{portResult.open_ports_count}</b>
                  </div>

                  <div className="table-container">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Port</th>
                          <th>Service</th>
                          <th>Status</th>
                          <th>Description</th>
                          <th>Risk</th>
                        </tr>
                      </thead>
                      <tbody>
                        {portResult.ports?.map((p) => (
                          <tr key={p.port}>
                            <td style={{ fontWeight: 700 }}>{p.port}</td>
                            <td>{p.service}</td>
                            <td>
                              {p.state === 'open' ? (
                                <span className="badge badge-malicious">OPEN</span>
                              ) : (
                                <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>Closed</span>
                              )}
                            </td>
                            <td style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>{p.description}</td>
                            <td>
                              {p.risk === 'High' ? (
                                <span className="badge badge-threat">HIGH RISK</span>
                              ) : '-'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

