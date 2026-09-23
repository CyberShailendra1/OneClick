import React, { useState, useRef } from 'react';
import { Package, Upload, Play, CheckCircle, AlertCircle, Download, Trash2 } from 'lucide-react';
import { scanApk } from '../api';
import { ScanResult } from '../types';

interface BatchScanProps {
  vtApiKey: string;
}

interface QueuedFile {
  id: string;
  file: File;
  status: 'pending' | 'scanning' | 'done' | 'error';
  result?: ScanResult;
  error?: string;
}

export const BatchScan: React.FC<BatchScanProps> = ({ vtApiKey }) => {
  const [queue, setQueue] = useState<QueuedFile[]>([]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFiles = (files: FileList | null) => {
    if (!files) return;
    const newItems: QueuedFile[] = [];
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      if (f.name.toLowerCase().endsWith('.apk')) {
        newItems.push({
          id: `${f.name}_${Date.now()}_${i}`,
          file: f,
          status: 'pending',
        });
      }
    }
    setQueue((prev) => [...prev, ...newItems]);
  };

  const handleRunBatch = async () => {
    if (isScanning || queue.length === 0) return;
    setIsScanning(true);

    const updatedQueue = [...queue];

    for (let i = 0; i < updatedQueue.length; i++) {
      if (updatedQueue[i].status === 'done') continue;

      updatedQueue[i].status = 'scanning';
      setQueue([...updatedQueue]);

      try {
        const res = await scanApk(updatedQueue[i].file, vtApiKey, false);
        updatedQueue[i].status = 'done';
        updatedQueue[i].result = res;
      } catch (err: any) {
        updatedQueue[i].status = 'error';
        updatedQueue[i].error = err.message || 'Scan failed';
      }

      setQueue([...updatedQueue]);
    }

    setIsScanning(false);
  };

  const handleClear = () => {
    if (isScanning) return;
    setQueue([]);
  };

  const handleExportBatchJson = () => {
    const data = queue.map((q) => ({
      filename: q.file.name,
      status: q.status,
      sha256: q.result?.sha256,
      verdict: q.result?.known_threat ? 'Known Threat' : q.result?.ml_result?.label,
      risk_score: q.result?.known_threat ? 100 : q.result?.ml_result?.risk_score,
      error: q.error,
    }));
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `oneclick_batch_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const completedCount = queue.filter((q) => q.status === 'done' || q.status === 'error').length;
  const progressPercent = queue.length > 0 ? (completedCount / queue.length) * 100 : 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Package size={22} color="var(--teal)" /> Batch APK Scanner
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '13.5px' }}>
              Upload and analyze multiple Android packages concurrently.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              className="btn btn-secondary"
              onClick={() => fileInputRef.current?.click()}
              disabled={isScanning}
            >
              <Upload size={16} /> Add APKs
            </button>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".apk"
              onChange={(e) => handleFiles(e.target.files)}
              style={{ display: 'none' }}
            />
            <button
              className="btn btn-primary"
              onClick={handleRunBatch}
              disabled={isScanning || queue.length === 0}
            >
              <Play size={16} /> Run Batch ({queue.length})
            </button>
            {queue.length > 0 && (
              <>
                <button
                  className="btn btn-secondary"
                  onClick={handleExportBatchJson}
                  title="Export results to JSON"
                >
                  <Download size={16} /> Export
                </button>
                <button
                  className="btn btn-danger"
                  onClick={handleClear}
                  disabled={isScanning}
                  title="Clear Queue"
                >
                  <Trash2 size={16} />
                </button>
              </>
            )}
          </div>
        </div>

        {/* Progress Bar */}
        {queue.length > 0 && (
          <div style={{ marginBottom: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12.5px', marginBottom: '6px' }}>
              <span>Progress: {completedCount} / {queue.length} files scanned</span>
              <span>{progressPercent.toFixed(0)}%</span>
            </div>
            <div style={{ height: '8px', background: 'var(--bg-card-alt)', borderRadius: '4px', overflow: 'hidden' }}>
              <div style={{
                height: '100%', width: `${progressPercent}%`, background: 'var(--teal)',
                transition: 'width 0.3s ease'
              }} />
            </div>
          </div>
        )}

        {/* Queue Table */}
        {queue.length === 0 ? (
          <div
            className="dropzone"
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload size={32} color="var(--teal)" style={{ margin: '0 auto 10px' }} />
            <h4 style={{ fontWeight: 700, fontSize: '15px' }}>Drop multiple APKs here</h4>
            <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Select multiple .apk files to batch scan</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>File Name</th>
                  <th>Size</th>
                  <th>Status</th>
                  <th>Verdict</th>
                  <th>Risk Score</th>
                  <th>SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {queue.map((item, idx) => {
                  const verdict = item.result?.known_threat
                    ? 'Known Threat'
                    : item.result?.ml_result?.label || '-';
                  const score = item.result?.known_threat
                    ? 100
                    : item.result?.ml_result?.risk_score;

                  let badgeClass = 'badge-safe';
                  if (verdict === 'Suspicious') badgeClass = 'badge-suspicious';
                  if (verdict === 'Malicious' || verdict === 'Known Threat') badgeClass = 'badge-malicious';

                  return (
                    <tr key={item.id}>
                      <td>{idx + 1}</td>
                      <td style={{ fontWeight: 600 }}>{item.file.name}</td>
                      <td>{(item.file.size / (1024 * 1024)).toFixed(2)} MB</td>
                      <td>
                        {item.status === 'pending' && <span style={{ color: 'var(--text-muted)' }}>Pending</span>}
                        {item.status === 'scanning' && <span style={{ color: 'var(--cyan)' }}>Scanning...</span>}
                        {item.status === 'done' && <span style={{ color: 'var(--green)' }}>Complete</span>}
                        {item.status === 'error' && <span style={{ color: 'var(--red)' }}>Error</span>}
                      </td>
                      <td>
                        {item.result ? (
                          <span className={`badge ${badgeClass}`}>{verdict}</span>
                        ) : '-'}
                      </td>
                      <td>
                        {score !== undefined ? `${score.toFixed(0)}%` : '-'}
                      </td>
                      <td>
                        <code style={{ fontSize: '11px' }}>
                          {item.result?.sha256 ? `${item.result.sha256.substring(0, 16)}...` : '-'}
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

