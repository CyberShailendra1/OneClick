import React, { useState, useEffect } from 'react';
import {
  Globe, Search, AlertTriangle, ShieldCheck, ShieldAlert,
  ArrowRight, FileText, CheckCircle, ExternalLink, RefreshCw, Trash2
} from 'lucide-react';
import {
  scanUrl, scanMessage, investigateUrl,
  getUrlHistory, setUrlAction, clearUrlHistory
} from '../api';
import { UrlScanResult, InvestigationResult, UrlHistoryRecord } from '../types';

interface PhishingScannerProps {
  vtApiKey: string;
}

export const PhishingScanner: React.FC<PhishingScannerProps> = ({ vtApiKey }) => {
  const [subTab, setSubTab] = useState<'scan' | 'message' | 'history'>('scan');
  const [singleUrl, setSingleUrl] = useState<string>('');
  const [messageText, setMessageText] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [singleResult, setSingleResult] = useState<UrlScanResult | null>(null);
  const [messageResults, setMessageResults] = useState<UrlScanResult[]>([]);
  const [investigating, setInvestigating] = useState<boolean>(false);
  const [investigationData, setInvestigationData] = useState<InvestigationResult | null>(null);
  const [urlHistory, setUrlHistory] = useState<UrlHistoryRecord[]>([]);

  const loadUrlHistory = async () => {
    try {
      const records = await getUrlHistory();
      setUrlHistory(records);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    if (subTab === 'history') {
      loadUrlHistory();
    }
  }, [subTab]);

  const handleScanSingleUrl = async () => {
    if (!singleUrl.trim()) return;
    setLoading(true);
    setSingleResult(null);
    setInvestigationData(null);
    try {
      const res = await scanUrl(singleUrl.trim(), vtApiKey);
      setSingleResult(res);
    } catch (err: any) {
      alert(`Error scanning URL: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleScanMessage = async () => {
    if (!messageText.trim()) return;
    setLoading(true);
    setMessageResults([]);
    try {
      const res = await scanMessage(messageText.trim(), vtApiKey);
      setMessageResults(res.results);
    } catch (err: any) {
      alert(`Error scanning message: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleInvestigate = async (url: string) => {
    setInvestigating(true);
    setInvestigationData(null);
    try {
      const res = await investigateUrl(url);
      setInvestigationData(res);
    } catch (err: any) {
      alert(`Investigation failed: ${err.message}`);
    } finally {
      setInvestigating(false);
    }
  };

  const handleSetAction = async (rowId: number, action: 'dismissed' | 'deleted_by_user') => {
    try {
      await setUrlAction(rowId, action);
      loadUrlHistory();
    } catch (err: any) {
      alert(`Action failed: ${err.message}`);
    }
  };

  const handleClearUrlHistory = async () => {
    if (!window.confirm('Clear all URL scan history?')) return;
    try {
      await clearUrlHistory();
      setUrlHistory([]);
    } catch (err: any) {
      alert(`Clear failed: ${err.message}`);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Globe size={22} color="var(--cyan)" /> Phishing & Malicious URL Scanner
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '13.5px' }}>
              Detect deceptive domains, punycode attacks, and inspect landing page redirects.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className={`btn ${subTab === 'scan' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setSubTab('scan')}
            >
              Single URL
            </button>
            <button
              className={`btn ${subTab === 'message' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setSubTab('message')}
            >
              Paste Message
            </button>
            <button
              className={`btn ${subTab === 'history' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setSubTab('history')}
            >
              URL History
            </button>
          </div>
        </div>

        {/* Sub-tab 1: Single URL Scan */}
        {subTab === 'scan' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', gap: '10px' }}>
              <input
                type="text"
                className="input-field"
                placeholder="Enter URL to check (e.g. https://secure-bank-login.xyz/verify)"
                value={singleUrl}
                onChange={(e) => setSingleUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleScanSingleUrl()}
              />
              <button className="btn btn-primary" onClick={handleScanSingleUrl} disabled={loading || !singleUrl.trim()} style={{ minWidth: '130px' }}>
                {loading ? 'Scanning...' : 'Scan URL'}
              </button>
            </div>

            {singleResult && (
              <div style={{ marginTop: '10px', background: 'var(--bg-card-alt)', borderRadius: '10px', padding: '20px', border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
                  <div>
                    <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Target URL</span>
                    <div style={{ fontSize: '15px', fontWeight: 600, wordBreak: 'break-all' }}>{singleResult.url}</div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span className={`badge ${singleResult.label === 'Safe' ? 'badge-safe' : singleResult.label === 'Suspicious' ? 'badge-suspicious' : 'badge-malicious'}`} style={{ fontSize: '14px', padding: '6px 14px' }}>
                      {singleResult.label} ({singleResult.score}%)
                    </span>
                    <button
                      className="btn btn-secondary"
                      onClick={() => handleInvestigate(singleResult.url)}
                      disabled={investigating}
                      style={{ fontSize: '13px', padding: '6px 12px' }}
                    >
                      {investigating ? 'Investigating...' : 'Deep Investigate'}
                    </button>
                  </div>
                </div>

                {singleResult.reasons.length > 0 && (
                  <div>
                    <h4 style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '8px' }}>Flagged Reasons:</h4>
                    <ul style={{ paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '13px' }}>
                      {singleResult.reasons.map((r, i) => (
                        <li key={i} style={{ color: 'var(--amber)' }}>{r}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Sub-tab 2: Paste Message Scan */}
        {subTab === 'message' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <textarea
              className="textarea-field"
              rows={4}
              placeholder="Paste SMS, WhatsApp, or email message containing URLs here..."
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-primary" onClick={handleScanMessage} disabled={loading || !messageText.trim()}>
                {loading ? 'Extracting & Scanning...' : 'Extract & Scan Links'}
              </button>
            </div>

            {messageResults.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '10px' }}>
                <h4 style={{ fontSize: '15px', fontWeight: 700 }}>URLs Found ({messageResults.length})</h4>
                {messageResults.map((item, idx) => (
                  <div key={idx} style={{ background: 'var(--bg-card-alt)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '13.5px' }}>{item.url}</div>
                      {item.reasons.length > 0 && (
                        <div style={{ color: 'var(--amber)', fontSize: '12px', marginTop: '4px' }}>
                          {item.reasons.join(' • ')}
                        </div>
                      )}
                    </div>
                    <span className={`badge ${item.label === 'Safe' ? 'badge-safe' : item.label === 'Suspicious' ? 'badge-suspicious' : 'badge-malicious'}`}>
                      {item.label} ({item.score}%)
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Sub-tab 3: URL History */}
        {subTab === 'history' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '12px' }}>
              {urlHistory.length > 0 && (
                <button className="btn btn-danger" onClick={handleClearUrlHistory} style={{ fontSize: '13px' }}>
                  <Trash2 size={14} /> Clear URL History
                </button>
              )}
            </div>
            {urlHistory.length === 0 ? (
              <p style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '30px 0' }}>No URL scans recorded yet.</p>
            ) : (
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>URL</th>
                      <th>Verdict</th>
                      <th>Risk</th>
                      <th>Action Status</th>
                      <th>Change Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {urlHistory.map((item) => (
                      <tr key={item.id}>
                        <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          {item.scanned_at ? new Date(item.scanned_at).toLocaleTimeString() : '-'}
                        </td>
                        <td style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {item.url}
                        </td>
                        <td>
                          <span className={`badge ${item.verdict === 'Safe' ? 'badge-safe' : item.verdict === 'Suspicious' ? 'badge-suspicious' : 'badge-malicious'}`}>
                            {item.verdict}
                          </span>
                        </td>
                        <td>{item.risk_score}%</td>
                        <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                          {item.action || 'none'}
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: '6px' }}>
                            <button className="btn btn-secondary" style={{ padding: '4px 8px', fontSize: '11px' }} onClick={() => handleSetAction(item.id, 'dismissed')}>
                              Dismiss
                            </button>
                            <button className="btn btn-danger" style={{ padding: '4px 8px', fontSize: '11px' }} onClick={() => handleSetAction(item.id, 'deleted_by_user')}>
                              Mark Deleted
                            </button>
                          </div>
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

      {/* Investigation Details Modal / Card */}
      {investigationData && (
        <div className="card" style={{ border: '1px solid var(--border-accent)', background: 'var(--bg-card-alt)' }}>
          <h3 style={{ fontSize: '17px', fontWeight: 800, marginBottom: '14px', color: 'var(--cyan)' }}>
            🔬 Static Landing-Page Investigation Report
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', marginBottom: '16px' }}>
            <div style={{ background: 'var(--bg-card)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Password Input Found</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: investigationData.has_password_field ? 'var(--red)' : 'var(--green)' }}>
                {investigationData.has_password_field ? 'YES ⚠️' : 'NO'}
              </div>
            </div>
            <div style={{ background: 'var(--bg-card)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Credit Card Field Found</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: investigationData.has_credit_card_field ? 'var(--red)' : 'var(--green)' }}>
                {investigationData.has_credit_card_field ? 'YES ⚠️' : 'NO'}
              </div>
            </div>
            <div style={{ background: 'var(--bg-card)', padding: '12px', borderRadius: '8px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Meta Refresh Redirect</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: investigationData.has_meta_refresh ? 'var(--amber)' : 'var(--green)' }}>
                {investigationData.has_meta_refresh ? 'YES' : 'NO'}
              </div>
            </div>
          </div>

          {investigationData.redirect_chain.length > 0 && (
            <div style={{ marginBottom: '14px' }}>
              <h4 style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '6px' }}>Redirect Chain:</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '12.5px' }}>
                {investigationData.redirect_chain.map((r, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ color: 'var(--teal)' }}>→</span> <code>{r}</code>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

