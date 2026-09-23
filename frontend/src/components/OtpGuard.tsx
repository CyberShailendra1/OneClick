import React, { useState } from 'react';
import { Lock, Shield, Copy, Check, Info } from 'lucide-react';
import { redactMessage } from '../api';

export const OtpGuard: React.FC = () => {
  const [inputText, setInputText] = useState<string>('');
  const [redactedText, setRedactedText] = useState<string>('');
  const [codesFound, setCodesFound] = useState<number | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  const handleRedact = async () => {
    if (!inputText.trim()) return;
    setLoading(true);
    try {
      const res = await redactMessage(inputText);
      setRedactedText(res.redacted_text);
      setCodesFound(res.codes_found);
    } catch (err: any) {
      alert(`Redaction failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (!redactedText) return;
    navigator.clipboard.writeText(redactedText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <div className="card">
        <div style={{ marginBottom: '18px' }}>
          <h2 style={{ fontSize: '20px', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Lock size={22} color="var(--teal)" /> OTP & Secret Code Redaction Guard
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '13.5px' }}>
            Prevent verification codes from leaking into tickets, screenshots, or logs by auto-masking sensitive tokens.
          </p>
        </div>

        <div style={{
          background: 'rgba(20, 184, 166, 0.08)', border: '1px solid rgba(20, 184, 166, 0.2)',
          borderRadius: '8px', padding: '12px 16px', marginBottom: '20px', display: 'flex', gap: '10px',
          alignItems: 'flex-start', fontSize: '13px'
        }}>
          <Info size={18} color="var(--teal)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div style={{ color: 'var(--text-main)', lineHeight: 1.5 }}>
            <b>Privacy Guarantee:</b> The actual OTP value is masked in memory and never persisted in database logs or reports. Only the sanitized message is returned.
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
          {/* Input side */}
          <div>
            <label style={{ display: 'block', fontSize: '13.5px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-muted)' }}>
              Original Message (with sensitive codes)
            </label>
            <textarea
              className="textarea-field"
              rows={6}
              placeholder="e.g. Your verification OTP is 482910. Do not share this code with anyone including bank representatives."
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '10px' }}>
              <button
                className="btn btn-primary"
                onClick={handleRedact}
                disabled={loading || !inputText.trim()}
              >
                {loading ? 'Redacting...' : 'Mask Sensitive Codes'}
              </button>
            </div>
          </div>

          {/* Redacted output side */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <label style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-muted)' }}>
                Sanitized & Redacted Output
              </label>
              {codesFound !== null && (
                <span className="badge" style={{ background: 'rgba(20, 184, 166, 0.15)', color: 'var(--teal)' }}>
                  {codesFound} code{codesFound === 1 ? '' : 's'} masked
                </span>
              )}
            </div>

            <div style={{
              background: 'var(--bg-card-alt)', border: '1px solid var(--border)', borderRadius: '8px',
              padding: '12px 14px', minHeight: '144px', color: redactedText ? 'var(--text-main)' : 'var(--text-muted)',
              fontSize: '14px', whiteSpace: 'pre-wrap', lineHeight: 1.5, position: 'relative'
            }}>
              {redactedText || 'Redacted message will appear here...'}
            </div>

            {redactedText && (
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '10px' }}>
                <button className="btn btn-secondary" onClick={handleCopy}>
                  {copied ? <Check size={16} color="var(--green)" /> : <Copy size={16} />}
                  <span>{copied ? 'Copied!' : 'Copy Redacted Text'}</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

