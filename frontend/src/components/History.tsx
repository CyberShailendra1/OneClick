import React, { useState, useEffect } from 'react';
import { History as HistoryIcon, Search, RefreshCw, Trash2, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { getHistory, clearHistory } from '../api';
import { HistoryRecord } from '../types';

export const History: React.FC = () => {
  const [history, setHistory] = useState<HistoryRecord[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [clearing, setClearing] = useState<boolean>(false);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const records = await getHistory(100);
      setHistory(records);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleClear = async () => {
    if (!window.confirm('Are you sure you want to clear all scan history from the database?')) {
      return;
    }
    setClearing(true);
    try {
      await clearHistory();
      setHistory([]);
    } catch (err: any) {
      alert(`Failed to clear: ${err.message}`);
    } finally {
      setClearing(false);
    }
  };

  const filtered = history.filter((item) => {
    const term = searchTerm.toLowerCase();
    return (
      (item.filename && item.filename.toLowerCase().includes(term)) ||
      (item.sha256 && item.sha256.toLowerCase().includes(term)) ||
      (item.verdict && item.verdict.toLowerCase().includes(term))
    );
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '14px' }}>
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <HistoryIcon size={22} color="var(--teal)" /> Scan History
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '13.5px' }}>
              Persistent scan records from the local SQLite database.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button className="btn btn-secondary" onClick={loadHistory} disabled={loading}>
              <RefreshCw size={15} className={loading ? 'animate-spin' : ''} /> Refresh
            </button>
            {history.length > 0 && (
              <button className="btn btn-danger" onClick={handleClear} disabled={clearing}>
                <Trash2 size={15} /> Clear History
              </button>
            )}
          </div>
        </div>

        {/* Search Bar */}
        <div style={{ position: 'relative', marginBottom: '16px' }}>
          <Search size={18} color="var(--text-muted)" style={{ position: 'absolute', left: '14px', top: '12px' }} />
          <input
            type="text"
            className="input-field"
            placeholder="Filter scans by file name, SHA-256 hash, or verdict..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ paddingLeft: '42px' }}
          />
        </div>

        {/* Table */}
        {loading ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
            Loading records...
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '50px 0', color: 'var(--text-muted)' }}>
            <CheckCircle2 size={36} color="var(--border-light)" style={{ margin: '0 auto 10px' }} />
            <p>{searchTerm ? 'No matching scans found.' : 'No scans in history yet. Upload an APK to begin!'}</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Filename</th>
                  <th>Verdict</th>
                  <th>Risk Score</th>
                  <th>VT Positives</th>
                  <th>SHA-256 Hash</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((row) => {
                  let badgeClass = 'badge-safe';
                  if (row.verdict === 'Suspicious') badgeClass = 'badge-suspicious';
                  if (row.verdict === 'Malicious' || row.verdict === 'Known Threat') badgeClass = 'badge-malicious';

                  return (
                    <tr key={row.id}>
                      <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                        {row.scanned_at ? new Date(row.scanned_at).toLocaleString() : 'Recent'}
                      </td>
                      <td style={{ fontWeight: 600 }}>{row.filename}</td>
                      <td>
                        <span className={`badge ${badgeClass}`}>{row.verdict}</span>
                      </td>
                      <td>
                        <span style={{ fontWeight: 700 }}>{row.risk_score?.toFixed(0)}%</span>
                      </td>
                      <td>
                        {row.vt_positives > 0 ? (
                          <span style={{ color: 'var(--red)', fontWeight: 700 }}>{row.vt_positives} engines</span>
                        ) : (
                          <span style={{ color: 'var(--green)' }}>0 engines</span>
                        )}
                      </td>
                      <td>
                        <code style={{ fontSize: '11.5px', color: 'var(--teal)' }}>
                          {row.sha256}
                        </code>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

