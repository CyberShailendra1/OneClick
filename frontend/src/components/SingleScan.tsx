import React, { useState, useRef } from 'react';
import {
  Upload, FileText, Download, ShieldCheck, AlertCircle, AlertTriangle,
  Info, Cpu, Lock, Terminal, Globe, ChevronRight, CheckCircle2, XCircle
} from 'lucide-react';
import { scanApk, downloadReport } from '../api';
import { ScanResult } from '../types';

interface SingleScanProps {
  vtApiKey: string;
}

export const SingleScan: React.FC<SingleScanProps> = ({ vtApiKey }) => {
  const [file, setFile] = useState<File | null>(null);
  const [advanced, setAdvanced] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(false);
  const [downloadingFormat, setDownloadingFormat] = useState<'pdf' | 'json' | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'permissions' | 'iocs' | 'ai' | 'components'>('permissions');
  const [isDragActive, setIsDragActive] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setIsDragActive(true);
    } else if (e.type === 'dragleave') {
      setIsDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const dropped = e.dataTransfer.files[0];
      if (dropped.name.toLowerCase().endsWith('.apk')) {
        setFile(dropped);
        setError(null);
      } else {
        setError('Please upload a valid .apk file');
      }
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selected = e.target.files[0];
      if (selected.name.toLowerCase().endsWith('.apk')) {
        setFile(selected);
        setError(null);
      } else {
        setError('Please upload a valid .apk file');
      }
    }
  };

  const handleStartScan = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await scanApk(file, vtApiKey, advanced);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (format: 'pdf' | 'json') => {
    if (!file) return;
    setDownloadingFormat(format);
    try {
      await downloadReport(file, format, vtApiKey);
    } catch (err: any) {
      alert(`Download failed: ${err.message}`);
    } finally {
      setDownloadingFormat(null);
    }
  };

  // Determine colors based on ML / Threat verdict
  const verdict = result?.known_threat
    ? 'Known Threat'
    : result?.ml_result?.label || 'Safe';
  const riskScore = result?.known_threat ? 100 : result?.ml_result?.risk_score || 0;

  let verdictColor = 'var(--green)';
  let verdictBadgeClass = 'badge-safe';
  if (verdict === 'Suspicious') {
    verdictColor = 'var(--amber)';
    verdictBadgeClass = 'badge-suspicious';
  } else if (verdict === 'Malicious' || verdict === 'Known Threat') {
    verdictColor = 'var(--red)';
    verdictBadgeClass = 'badge-malicious';
  }

  // Calculate SVG arc for gauge
  const radius = 70;
  const strokeWidth = 14;
  const circumference = Math.PI * radius; // half circle
  const strokeDashoffset = circumference - (riskScore / 100) * circumference;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Hero Banner */}
      <div className="card" style={{
        background: 'linear-gradient(135deg, rgba(16, 23, 38, 0.95), rgba(20, 184, 166, 0.08))',
        border: '1px solid var(--border-light)',
        padding: '24px 28px'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <h1 style={{ fontSize: '24px', fontWeight: 800, color: '#fff', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              🛡️ Multi-Layer APK Threat Analyzer
            </h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
              Comprehensive Android analysis: VirusTotal signature lookup + Androguard static decompilation + Random Forest AI scoring.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <span className="badge" style={{ background: 'rgba(6, 182, 212, 0.1)', color: 'var(--cyan)' }}>
              🔎 VirusTotal Signatures
            </span>
            <span className="badge" style={{ background: 'rgba(20, 184, 166, 0.1)', color: 'var(--teal)' }}>
              🧬 Static Analysis
            </span>
            <span className="badge" style={{ background: 'rgba(59, 130, 246, 0.1)', color: 'var(--blue)' }}>
              🤖 AI Risk Classifier
            </span>
          </div>
        </div>
      </div>

      {/* Upload & Options Card */}
      <div className="card">
        <div
          className={`dropzone ${isDragActive ? 'drag-active' : ''}`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".apk"
            onChange={handleFileChange}
            style={{ display: 'none' }}
          />
          <div style={{
            width: '56px', height: '56px', borderRadius: '14px', margin: '0 auto 14px',
            background: 'rgba(20, 184, 166, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <Upload size={28} color="var(--teal)" />
          </div>
          <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '6px' }}>
            {file ? file.name : 'Choose or drop your APK file here'}
          </h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
            {file ? `${(file.size / (1024 * 1024)).toFixed(2)} MB • Ready to analyze` : 'Supports standard Android .apk installation packages'}
          </p>
        </div>

        {error && (
          <div style={{
            marginTop: '16px', padding: '12px 16px', borderRadius: '8px',
            background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)',
            color: '#fca5a5', display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13.5px'
          }}>
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '18px', flexWrap: 'wrap', gap: '12px' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '13.5px', color: 'var(--text-main)' }}>
            <input
              type="checkbox"
              checked={advanced}
              onChange={(e) => setAdvanced(e.target.checked)}
              style={{ accentColor: 'var(--teal)', width: '16px', height: '16px' }}
            />
            <span>Run Advanced Static Analysis (IOCs, Hardcoded URLs/IPs, Exported components)</span>
          </label>

          <button
            className="btn btn-primary"
            onClick={handleStartScan}
            disabled={!file || loading}
            style={{ minWidth: '150px' }}
          >
            {loading ? (
              <>
                <div className="animate-spin" style={{ width: '16px', height: '16px', border: '2px solid #042f2e', borderTopColor: 'transparent', borderRadius: '50%' }} />
                <span>Scanning APK...</span>
              </>
            ) : (
              <>
                <ShieldCheck size={18} />
                <span>Analyze APK</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Results View */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Top Verdict & Gauge Card */}
          <div className="card" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px', alignItems: 'center' }}>
            {/* Risk Gauge */}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <div style={{ position: 'relative', width: '200px', height: '120px', display: 'flex', justifyContent: 'center' }}>
                <svg width="200" height="120" viewBox="0 0 200 120">
                  {/* Background Arc */}
                  <path
                    d="M 20 100 A 70 70 0 0 1 180 100"
                    fill="none"
                    stroke="var(--bg-card-alt)"
                    strokeWidth={strokeWidth}
                    strokeLinecap="round"
                  />
                  {/* Colored Progress Arc */}
                  <path
                    d="M 20 100 A 70 70 0 0 1 180 100"
                    fill="none"
                    stroke={verdictColor}
                    strokeWidth={strokeWidth}
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                    style={{ transition: 'stroke-dashoffset 1s ease-out' }}
                  />
                </svg>
                {/* Score Number in center */}
                <div style={{ position: 'absolute', bottom: '0px', textAlign: 'center' }}>
                  <span style={{ fontSize: '32px', fontWeight: 800, color: '#fff' }}>
                    {riskScore.toFixed(0)}%
                  </span>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>
                    Risk Score
                  </div>
                </div>
              </div>
              <div style={{ marginTop: '12px' }}>
                <span className={`badge ${verdictBadgeClass}`} style={{ fontSize: '14px', padding: '6px 18px' }}>
                  {verdict}
                </span>
              </div>
            </div>

            {/* VirusTotal & Quick Stats */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Globe size={18} color="var(--cyan)" />
                VirusTotal Threat Intel
              </h3>

              {result.vt_result ? (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px' }}>
                  <div style={{ background: 'var(--bg-card-alt)', padding: '12px', borderRadius: '8px', textAlign: 'center' }}>
                    <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--red)' }}>
                      {result.vt_result.positives || result.vt_result.malicious || 0}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Malicious</div>
                  </div>
                  <div style={{ background: 'var(--bg-card-alt)', padding: '12px', borderRadius: '8px', textAlign: 'center' }}>
                    <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--amber)' }}>
                      {result.vt_result.suspicious || 0}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Suspicious</div>
                  </div>
                  <div style={{ background: 'var(--bg-card-alt)', padding: '12px', borderRadius: '8px', textAlign: 'center' }}>
                    <div style={{ fontSize: '20px', fontWeight: 800, color: 'var(--green)' }}>
                      {result.vt_result.harmless || (result.vt_result.total ? result.vt_result.total - (result.vt_result.positives || 0) : 0)}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Harmless / Undetected</div>
                  </div>
                </div>
              ) : (
                <div style={{ background: 'var(--bg-card-alt)', padding: '14px', borderRadius: '8px', fontSize: '13px', color: 'var(--text-muted)' }}>
                  No VirusTotal match found or no VT key supplied. Local heuristic analysis used.
                </div>
              )}

              {/* Download Report Actions */}
              <div style={{ display: 'flex', gap: '10px', marginTop: '6px' }}>
                <button
                  className="btn btn-secondary"
                  style={{ flex: 1 }}
                  onClick={() => handleDownload('pdf')}
                  disabled={downloadingFormat === 'pdf'}
                >
                  <Download size={15} />
                  <span>{downloadingFormat === 'pdf' ? 'Generating PDF...' : 'Download PDF'}</span>
                </button>
                <button
                  className="btn btn-secondary"
                  style={{ flex: 1 }}
                  onClick={() => handleDownload('json')}
                  disabled={downloadingFormat === 'json'}
                >
                  <FileText size={15} />
                  <span>{downloadingFormat === 'json' ? 'Generating JSON...' : 'Export JSON'}</span>
                </button>
              </div>
            </div>

            {/* Metadata Card */}
            <div style={{ background: 'var(--bg-card-alt)', padding: '16px', borderRadius: '10px', display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px' }}>
              <div style={{ fontWeight: 700, color: '#fff', marginBottom: '4px' }}>Package Details</div>
              <div><span style={{ color: 'var(--text-muted)' }}>App:</span> <b>{result.features?.app_name || 'N/A'}</b></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Package:</span> <code style={{ color: 'var(--teal)' }}>{result.features?.package_name || 'N/A'}</code></div>
              <div><span style={{ color: 'var(--text-muted)' }}>Version:</span> {result.features?.version_name || result.features?.version_code || 'N/A'}</div>
              <div><span style={{ color: 'var(--text-muted)' }}>SDKs:</span> Min {result.features?.min_sdk || '?'} / Target {result.features?.target_sdk || '?'}</div>
              <div style={{ wordBreak: 'break-all', fontSize: '11.5px', marginTop: '4px' }}>
                <span style={{ color: 'var(--text-muted)' }}>SHA256: </span>
                <code>{result.sha256}</code>
              </div>
            </div>
          </div>

          {/* Detailed Findings Tabs */}
          <div className="card" style={{ padding: '0px', overflow: 'hidden' }}>
            <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--bg-card-alt)' }}>
              {[
                { id: 'permissions', label: `Permissions (${result.features?.num_permissions || 0})`, icon: Lock },
                { id: 'iocs', label: 'Suspicious APIs & IOCs', icon: Terminal },
                { id: 'ai', label: 'AI Risk Factors', icon: Cpu },
                { id: 'components', label: 'Components & Libs', icon: Info },
              ].map((tab) => {
                const Icon = tab.icon;
                const isSelected = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '8px',
                      padding: '14px 20px', border: 'none', background: 'transparent',
                      color: isSelected ? 'var(--teal)' : 'var(--text-muted)',
                      fontWeight: isSelected ? 700 : 500, fontSize: '13.5px', cursor: 'pointer',
                      borderBottom: isSelected ? '2px solid var(--teal)' : '2px solid transparent',
                      transition: 'all 0.2s',
                    }}
                  >
                    <Icon size={16} />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>

            <div style={{ padding: '24px' }}>
              {/* Permissions Tab */}
              {activeTab === 'permissions' && (
                <div>
                  {result.features?.dangerous_permissions && result.features.dangerous_permissions.length > 0 && (
                    <div style={{ marginBottom: '20px' }}>
                      <h4 style={{ fontSize: '14px', color: 'var(--red)', fontWeight: 700, marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <AlertTriangle size={16} /> Dangerous Permissions ({result.features.dangerous_permissions.length})
                      </h4>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                        {result.features.dangerous_permissions.map((perm, idx) => (
                          <span key={idx} className="badge badge-malicious" style={{ textTransform: 'none' }}>
                            {perm}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div>
                    <h4 style={{ fontSize: '14px', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '10px' }}>
                      All Declared Permissions ({result.features?.requested_permissions?.length || 0})
                    </h4>
                    <div style={{ maxHeight: '250px', overflowY: 'auto', display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                      {result.features?.requested_permissions?.map((perm, idx) => (
                        <span key={idx} style={{ background: 'var(--bg-card-alt)', border: '1px solid var(--border)', borderRadius: '6px', padding: '4px 10px', fontSize: '12px', color: 'var(--text-main)' }}>
                          {perm}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* IOCs and APIs Tab */}
              {activeTab === 'iocs' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  {result.features?.suspicious_apis && result.features.suspicious_apis.length > 0 && (
                    <div>
                      <h4 style={{ fontSize: '14px', color: 'var(--amber)', fontWeight: 700, marginBottom: '8px' }}>
                        Suspicious Android API Invocations
                      </h4>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                        {result.features.suspicious_apis.map((api, idx) => (
                          <span key={idx} className="badge badge-suspicious" style={{ textTransform: 'none' }}>
                            {api}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {result.advanced?.hardcoded_urls && result.advanced.hardcoded_urls.length > 0 && (
                    <div>
                      <h4 style={{ fontSize: '14px', color: 'var(--cyan)', fontWeight: 700, marginBottom: '8px' }}>
                        Hardcoded External URLs Found in Bytecode
                      </h4>
                      <div style={{ maxHeight: '180px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        {result.advanced.hardcoded_urls.map((u, idx) => (
                          <div key={idx} style={{ background: 'var(--bg-card-alt)', padding: '6px 12px', borderRadius: '6px', fontSize: '12.5px', fontFamily: 'var(--font-mono)' }}>
                            {u}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {result.advanced?.hardcoded_ips && result.advanced.hardcoded_ips.length > 0 && (
                    <div>
                      <h4 style={{ fontSize: '14px', color: 'var(--red)', fontWeight: 700, marginBottom: '8px' }}>
                        Hardcoded IP Addresses
                      </h4>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                        {result.advanced.hardcoded_ips.map((ip, idx) => (
                          <span key={idx} className="badge badge-malicious" style={{ textTransform: 'none' }}>
                            {ip}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* AI Risk Factors Tab */}
              {activeTab === 'ai' && (
                <div>
                  <h4 style={{ fontSize: '14px', fontWeight: 700, color: '#fff', marginBottom: '12px' }}>
                    Top AI Scoring Factors & Indicators
                  </h4>
                  {result.ml_result?.reasons && result.ml_result.reasons.length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {result.ml_result.reasons.map((reason, idx) => (
                        <div key={idx} style={{
                          background: 'var(--bg-card-alt)', padding: '10px 14px', borderRadius: '8px',
                          display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px'
                        }}>
                          <ChevronRight size={16} color="var(--teal)" />
                          <span>{reason}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                      No adverse risk indicators flagged by the model.
                    </p>
                  )}
                </div>
              )}

              {/* Components Tab */}
              {activeTab === 'components' && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
                  <div style={{ background: 'var(--bg-card-alt)', padding: '14px', borderRadius: '8px' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '4px' }}>Exported Activities</div>
                    <div style={{ fontSize: '20px', fontWeight: 700, color: '#fff' }}>
                      {result.advanced?.exported_components?.activities?.length || 0}
                    </div>
                  </div>
                  <div style={{ background: 'var(--bg-card-alt)', padding: '14px', borderRadius: '8px' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '4px' }}>Exported Services</div>
                    <div style={{ fontSize: '20px', fontWeight: 700, color: '#fff' }}>
                      {result.advanced?.exported_components?.services?.length || 0}
                    </div>
                  </div>
                  <div style={{ background: 'var(--bg-card-alt)', padding: '14px', borderRadius: '8px' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '4px' }}>Native (.so) Libraries</div>
                    <div style={{ fontSize: '20px', fontWeight: 700, color: '#fff' }}>
                      {result.advanced?.native_libraries?.length || 0}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

