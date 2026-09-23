import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  XCircle,
  PhoneCall,
  ExternalLink,
  LifeBuoy,
  Search,
  Sparkles,
  HelpCircle,
  Copy,
  Check,
  AlertOctagon,
  ArrowRight,
  Info
} from 'lucide-react';
import { smartAnalyze } from '../api';
import { SmartAnalyzeResult } from '../types';

interface CitizenShieldProps {
  vtApiKey?: string;
  onNavigateToTab?: (tabId: string) => void;
}

export const CitizenShield: React.FC<CitizenShieldProps> = ({ vtApiKey, onNavigateToTab }) => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SmartAnalyzeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [showHelplineGuide, setShowHelplineGuide] = useState(false);
  const [showIncidentGuide, setShowIncidentGuide] = useState(false);

  const handleScan = async (inputText?: string) => {
    const textToScan = inputText !== undefined ? inputText : query;
    if (!textToScan.trim()) {
      setError('Please enter or paste a Phone number, UPI ID, Link, or Message to analyze.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await smartAnalyze(textToScan, vtApiKey);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Analysis failed. Please ensure the backend server is reachable.');
    } finally {
      setLoading(false);
    }
  };

  const handlePaste = async () => {
    try {
      const clipText = await navigator.clipboard.readText();
      if (clipText) {
        setQuery(clipText);
        handleScan(clipText);
      }
    } catch {
      // clipboard permission denied or not supported
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Hero Banner for Citizen / Non-Tech Users */}
      <div
        style={{
          background: 'linear-gradient(135deg, rgba(20, 184, 166, 0.12), rgba(6, 182, 212, 0.08), rgba(99, 102, 241, 0.08))',
          border: '1px solid rgba(20, 184, 166, 0.3)',
          borderRadius: '16px',
          padding: '28px',
          boxShadow: '0 8px 30px rgba(0, 0, 0, 0.25)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ maxWidth: '820px' }}>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '4px 12px', borderRadius: '999px', background: 'rgba(20, 184, 166, 0.2)', color: 'var(--teal)', fontSize: '12.5px', fontWeight: 600, marginBottom: '12px' }}>
              <Sparkles size={14} />
              <span>Universal Scam Guard • Plain-Language Intelligence</span>
            </div>
            <h1 style={{ fontSize: '28px', fontWeight: 800, color: '#fff', marginBottom: '8px', letterSpacing: '-0.5px' }}>
              Is this Call, Message, or Link Legitimate or a Scam?
            </h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '15px', lineHeight: 1.6 }}>
              Received an unexpected <b>WhatsApp message, OTP request, lottery notification, job task offer, or unfamiliar UPI handle</b>? Paste it below. The Smart AI Engine immediately checks for fraud patterns and returns a clear, actionable verdict without confusing jargon.
            </p>
          </div>

          {/* Emergency 1930 Helpline Button */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', minWidth: '220px' }}>
            <a
              href="tel:1930"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '10px',
                background: 'linear-gradient(135deg, #ef4444, #dc2626)',
                color: '#fff',
                padding: '12px 18px',
                borderRadius: '10px',
                textDecoration: 'none',
                fontWeight: 700,
                fontSize: '15px',
                boxShadow: '0 4px 14px rgba(239, 68, 68, 0.4)',
                transition: 'transform 0.2s',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.transform = 'translateY(-2px)')}
              onMouseLeave={(e) => (e.currentTarget.style.transform = 'translateY(0)')}
            >
              <PhoneCall size={18} />
              <span>Cyber Helpline 1930</span>
            </a>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={() => setShowHelplineGuide(true)}
                className="btn btn-secondary"
                style={{ flex: 1, fontSize: '11.5px', padding: '6px 8px' }}
              >
                How 1930 Works
              </button>
              <button
                onClick={() => setShowIncidentGuide(true)}
                className="btn btn-secondary"
                style={{ flex: 1, fontSize: '11.5px', padding: '6px 8px', color: 'var(--amber)' }}
              >
                Accidentally Clicked?
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main One-Box Search Input */}
      <div className="card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <label style={{ fontWeight: 700, fontSize: '16px', color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Search size={18} color="var(--teal)" />
            <span>Analyze any Number, Web Link, UPI Handle, or Text Message:</span>
          </label>
          <button
            onClick={handlePaste}
            className="btn btn-secondary"
            style={{ padding: '6px 12px', fontSize: '12px' }}
            title="Paste from clipboard"
          >
            📋 Paste from Clipboard
          </button>
        </div>

        <div style={{ position: 'relative' }}>
          <textarea
            className="input-field"
            rows={4}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type or paste query here... For example:
• Phone number: +91 98765 43210
• UPI ID: payment-officer@paytm
• Website link: http://sbi-kyc-update.com/login
• Full SMS or message text"
            style={{ fontSize: '14.5px', lineHeight: 1.5, resize: 'vertical' }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && e.ctrlKey) {
                e.preventDefault();
                handleScan();
              }
            }}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '14px', flexWrap: 'wrap', gap: '10px' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            💡 Privacy Guarantee: Secret OTPs and authentication pins are masked automatically before analysis.
          </span>
          <div style={{ display: 'flex', gap: '10px' }}>
            {query && (
              <button
                className="btn btn-secondary"
                onClick={() => { setQuery(''); setResult(null); setError(null); }}
              >
                Clear
              </button>
            )}
            <button
              className="btn btn-primary"
              onClick={() => handleScan()}
              disabled={loading}
              style={{ minWidth: '150px' }}
            >
              {loading ? 'Analyzing...' : '🔍 Analyze Query'}
            </button>
          </div>
        </div>

        {error && (
          <div style={{ marginTop: '16px', padding: '12px 16px', borderRadius: '8px', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.4)', color: '#fca5a5', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <XCircle size={18} />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Result Display Card (Traffic Light / Plain Language) */}
      {result && (
        <div
          className="card"
          style={{
            borderWidth: '2px',
            borderColor:
              result.level === 'danger'
                ? 'var(--red)'
                : result.level === 'caution'
                ? 'var(--amber)'
                : 'var(--green)',
            background:
              result.level === 'danger'
                ? 'rgba(239, 68, 68, 0.05)'
                : result.level === 'caution'
                ? 'rgba(245, 158, 11, 0.05)'
                : 'rgba(34, 197, 94, 0.05)',
            padding: '28px',
          }}
        >
          {/* Top Status Header */}
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px', marginBottom: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
              <div
                style={{
                  width: '56px',
                  height: '56px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  background:
                    result.level === 'danger'
                      ? 'rgba(239, 68, 68, 0.2)'
                      : result.level === 'caution'
                      ? 'rgba(245, 158, 11, 0.2)'
                      : 'rgba(34, 197, 94, 0.2)',
                  border: `2px solid ${
                    result.level === 'danger'
                      ? 'var(--red)'
                      : result.level === 'caution'
                      ? 'var(--amber)'
                      : 'var(--green)'
                  }`,
                }}
              >
                {result.level === 'danger' && <AlertOctagon size={32} color="var(--red)" />}
                {result.level === 'caution' && <AlertTriangle size={32} color="var(--amber)" />}
                {result.level === 'safe' && <ShieldCheck size={32} color="var(--green)" />}
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span
                    style={{
                      padding: '3px 10px',
                      borderRadius: '999px',
                      fontSize: '11px',
                      fontWeight: 800,
                      textTransform: 'uppercase',
                      letterSpacing: '1px',
                      background:
                        result.level === 'danger'
                          ? 'var(--red)'
                          : result.level === 'caution'
                          ? 'var(--amber)'
                          : 'var(--green)',
                      color: '#fff',
                    }}
                  >
                    {result.level === 'danger' ? 'DANGER (MALICIOUS)' : result.level === 'caution' ? 'CAUTION (SUSPICIOUS)' : 'VERIFIED SAFE'}
                  </span>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    Type: <b>{result.type.toUpperCase()}</b>
                  </span>
                </div>
                <h2 style={{ fontSize: '22px', fontWeight: 800, color: '#fff', marginTop: '4px' }}>
                  {result.title}
                </h2>
              </div>
            </div>

            {/* Quick Share or Copy Result */}
            <button
              onClick={() => handleCopy(`${result.title}\n\n${result.summary}\n\nAction Plan:\n${result.actions.join('\n')}`)}
              className="btn btn-secondary"
              style={{ fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              {copied ? <Check size={16} color="var(--green)" /> : <Copy size={16} />}
              <span>{copied ? 'Copied' : 'Share / Copy Report'}</span>
            </button>
          </div>

          {/* Simple Explanation */}
          <div
            style={{
              padding: '16px',
              borderRadius: '10px',
              background: 'rgba(0, 0, 0, 0.25)',
              border: '1px solid var(--border)',
              marginBottom: '24px',
            }}
          >
            <h4 style={{ fontSize: '14px', fontWeight: 700, color: '#fff', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Info size={16} color="var(--cyan)" />
              <span>Assessment & Findings</span>
            </h4>
            <p style={{ color: '#e2e8f0', fontSize: '15px', lineHeight: 1.6, margin: 0 }}>
              {result.summary}
            </p>
          </div>

          {/* Action Steps */}
          <div style={{ marginBottom: '24px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 800, color: '#fff', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>👉</span>
              <span>Recommended Action Steps</span>
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {result.actions.map((act, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '12px',
                    padding: '12px 16px',
                    borderRadius: '8px',
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border)',
                  }}
                >
                  <div
                    style={{
                      width: '24px',
                      height: '24px',
                      borderRadius: '50%',
                      background: 'rgba(20, 184, 166, 0.2)',
                      color: 'var(--teal)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '12px',
                      fontWeight: 700,
                      flexShrink: 0,
                    }}
                  >
                    {idx + 1}
                  </div>
                  <div style={{ color: '#f1f5f9', fontSize: '14px', lineHeight: 1.5 }}>
                    {act}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Redacted Message Preview or Detected Threat Tags */}
          {result.details && (
            <div style={{ borderTop: '1px solid var(--border)', paddingTop: '18px' }}>
              {result.details.redacted_preview && (
                <div style={{ marginBottom: '14px' }}>
                  <div style={{ fontSize: '12.5px', color: 'var(--text-muted)', marginBottom: '6px' }}>
                    🔒 Redacted Message Preview (Confidential OTPs/Codes have been masked):
                  </div>
                  <pre
                    style={{
                      background: 'rgba(0,0,0,0.4)',
                      padding: '12px',
                      borderRadius: '8px',
                      color: 'var(--cyan)',
                      fontSize: '13px',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                      margin: 0,
                    }}
                  >
                    {result.details.redacted_preview}
                  </pre>
                </div>
              )}

              {result.details.threats_detected && result.details.threats_detected.length > 0 && (
                <div>
                  <div style={{ fontSize: '12.5px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                    Detected Threat Flags:
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                    {result.details.threats_detected.map((t: string, idx: number) => (
                      <span
                        key={idx}
                        style={{
                          padding: '4px 10px',
                          borderRadius: '6px',
                          fontSize: '12px',
                          background: 'rgba(239, 68, 68, 0.15)',
                          color: '#f87171',
                          border: '1px solid rgba(239, 68, 68, 0.3)',
                        }}
                      >
                        ⚠️ {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Quick Helpline Callouts if Danger */}
          {result.level === 'danger' && (
            <div
              style={{
                marginTop: '22px',
                padding: '16px',
                borderRadius: '10px',
                background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(220, 38, 38, 0.1))',
                border: '1px solid rgba(239, 68, 68, 0.4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '12px',
              }}
            >
              <div>
                <div style={{ fontWeight: 800, color: '#f87171', fontSize: '15px' }}>
                  Have funds already been deducted? Do not panic.
                </div>
                <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                  Contact National Helpline 1930 immediately. Reports lodged within the first 2 hours yield an 85% transaction freeze success rate.
                </div>
              </div>
              <a
                href="tel:1930"
                style={{
                  background: 'var(--red)',
                  color: '#fff',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  textDecoration: 'none',
                  fontWeight: 700,
                  fontSize: '13px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <PhoneCall size={15} />
                <span>Call 1930 Now</span>
              </a>
            </div>
          )}
        </div>
      )}

      {/* 4 Golden Security Rules */}
      <div
        style={{
          background: 'rgba(16, 23, 38, 0.7)',
          border: '1px solid var(--border)',
          borderRadius: '14px',
          padding: '24px',
        }}
      >
        <h3 style={{ fontSize: '16px', fontWeight: 800, color: '#fff', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <LifeBuoy size={18} color="var(--teal)" />
          <span>4 Essential Security Principles for Digital Safety</span>
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px' }}>
          <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff', marginBottom: '6px' }}>🔑 1. Receiving Money Never Requires a PIN</div>
            <p style={{ color: 'var(--text-muted)', fontSize: '12.5px', lineHeight: 1.5, margin: 0 }}>
              Entering a UPI PIN or scanning a recipient QR code always debits funds from your account. You never enter a PIN to receive a credit.
            </p>
          </div>

          <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff', marginBottom: '6px' }}>👮 2. Law Enforcement Does Not Issue "Digital Arrests"</div>
            <p style={{ color: 'var(--text-muted)', fontSize: '12.5px', lineHeight: 1.5, margin: 0 }}>
              Police, CBI, Customs, and judicial agencies never execute arrests or demand security deposits over WhatsApp, Skype, or video calls.
            </p>
          </div>

          <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff', marginBottom: '6px' }}>📲 3. Never Sideload Unverified APK Packages</div>
            <p style={{ color: 'var(--text-muted)', fontSize: '12.5px', lineHeight: 1.5, margin: 0 }}>
              Never install `.apk` files received via messaging apps. Cloned banking and wedding invitation APKs are designed to intercept SMS OTPs and control devices.
            </p>
          </div>

          <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '15px', fontWeight: 700, color: '#fff', marginBottom: '6px' }}>⏳ 4. Observe the 2-Hour Golden Window (1930)</div>
            <p style={{ color: 'var(--text-muted)', fontSize: '12.5px', lineHeight: 1.5, margin: 0 }}>
              If unauthorized debits occur, dial 1930 immediately and file a report on cybercrime.gov.in to initiate an inter-bank transaction freeze.
            </p>
          </div>
        </div>
      </div>

      {/* Modal: 1930 Helpline Guide */}
      {showHelplineGuide && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.75)',
            backdropFilter: 'blur(5px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
            padding: '20px',
          }}
        >
          <div className="card" style={{ maxWidth: '580px', width: '100%', maxHeight: '90vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <PhoneCall size={22} color="var(--red)" />
                <h3 style={{ fontSize: '18px', fontWeight: 800 }}>National Cybercrime Helpline (1930) Protocol</h3>
              </div>
              <button onClick={() => setShowHelplineGuide(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '18px' }}>
                ✕
              </button>
            </div>

            <div style={{ fontSize: '14px', lineHeight: 1.6, color: '#e2e8f0', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <p>
                <b>1930</b> is the official toll-free national cybercrime helpline operated by the Ministry of Home Affairs (I4C) dedicated to mitigating financial cyber frauds.
              </p>

              <div style={{ background: 'rgba(239, 68, 68, 0.1)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
                <b>Information required when calling 1930:</b>
                <ul style={{ margin: '8px 0 0 18px', padding: 0, fontSize: '13px' }}>
                  <li>Your originating bank account number and IFSC code</li>
                  <li>Exact deducted amount and transaction timestamp</li>
                  <li>UPI UTR / Bank Reference Number from the transaction SMS</li>
                  <li>Suspect phone number, UPI handle, or beneficiary account</li>
                </ul>
              </div>

              <p>
                Calling 1930 triggers immediate integration with the Citizen Financial Cyber Fraud Management System (CFCFRMS), alerting nodal officers across commercial banks to freeze destination wallets.
              </p>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '8px' }}>
                <a
                  href="https://cybercrime.gov.in"
                  target="_blank"
                  rel="noreferrer"
                  className="btn btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}
                >
                  <span>Visit cybercrime.gov.in</span>
                  <ExternalLink size={13} />
                </a>
                <button className="btn btn-primary" onClick={() => setShowHelplineGuide(false)}>
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Incident Response Guide (Link Clicked) */}
      {showIncidentGuide && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.75)',
            backdropFilter: 'blur(5px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
            padding: '20px',
          }}
        >
          <div className="card" style={{ maxWidth: '620px', width: '100%', maxHeight: '90vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <AlertTriangle size={22} color="var(--amber)" />
                <h3 style={{ fontSize: '18px', fontWeight: 800 }}>Accidental Phishing Link Clicked? Response Checklist</h3>
              </div>
              <button onClick={() => setShowIncidentGuide(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '18px' }}>
                ✕
              </button>
            </div>

            <div style={{ fontSize: '14px', lineHeight: 1.6, color: '#e2e8f0', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ padding: '10px 14px', borderRadius: '8px', background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', color: '#fcd34d' }}>
                Stay calm. Simply opening a page does not compromise your account unless credentials were submitted or unauthorized files were downloaded. Execute these immediate containment steps:
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div style={{ padding: '10px', background: 'var(--bg-card)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <b>1. Close the Browser Tab Immediately:</b> Do not enter passwords, card numbers, or one-time codes.
                </div>
                <div style={{ padding: '10px', background: 'var(--bg-card)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <b>2. Check Download Directory:</b> Inspect your phone or desktop "Downloads" folder. If any `.apk`, `.exe`, or `.zip` was triggered, delete it immediately without opening.
                </div>
                <div style={{ padding: '10px', background: 'var(--bg-card)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <b>3. Rotate Compromised Credentials:</b> If credentials were submitted, access the authentic service from an independent browser, change your password immediately, and terminate active sessions.
                </div>
                <div style={{ padding: '10px', background: 'var(--bg-card)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <b>4. Freeze Payment Cards:</b> If payment card credentials were typed, open your official banking application and immediately lock or freeze card transactions.
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '8px' }}>
                <button className="btn btn-primary" onClick={() => setShowIncidentGuide(false)}>
                  Close Checklist
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
