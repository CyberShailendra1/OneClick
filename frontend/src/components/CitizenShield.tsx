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

  const sampleScenarios = [
    {
      title: '⚡ Electricity Disconnection SMS',
      text: 'Dear Customer your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately contact our power officer at 9876543210 or click bit.ly/power-pay',
    },
    {
      title: '📦 India Post / Courier Package Hold',
      text: 'Your package is on hold at Mumbai sorting hub due to missing house number. Update your details within 24 hours at indiapost-track-support.top/address to avoid return.',
    },
    {
      title: '💼 Part-Time YouTube Like Job',
      text: 'Earn Rs 3000 to Rs 8000 daily by simply subscribing YouTube channels and rating hotels on Google. Send payment to vip_task@paytm to get your VIP task dashboard login.',
    },
    {
      title: '🚨 Digital Arrest / Police Notice',
      text: 'Urgent: A consignment under your Aadhaar containing illegal narcotics was seized by Customs at Delhi Airport. Join Skype video call immediately for CBI verification or arrest warrant will be issued.',
    },
  ];

  const handleScan = async (inputText?: string) => {
    const textToScan = inputText !== undefined ? inputText : query;
    if (!textToScan.trim()) {
      setError('Kuch toh type ya paste karein (Phone, UPI ID, Link ya SMS message)');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await smartAnalyze(textToScan, vtApiKey);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Analysis failed. Kripya check karein server online hai ya nahi.');
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
              <span>Aapki Suraksha Ka Pehredaar • Simple & 100% Free</span>
            </div>
            <h1 style={{ fontSize: '28px', fontWeight: 800, color: '#fff', marginBottom: '8px', letterSpacing: '-0.5px' }}>
              Kya yeh Call, Message ya Link Asli Hai Ya Fraud?
            </h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '15px', lineHeight: 1.6 }}>
              Agar aapko koi anjaan <b>WhatsApp message, OTP call, Lottery/Job offer, Electricity bill warning, ya UPI ID</b> par shaq hai — yahan paste karein. Hamara Smart AI Engine bina kisi technical jhanjhat ke turant batayega ki yeh safe hai ya fraud.
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
                1930 Kaise Kaam Karta Hai?
              </button>
              <button
                onClick={() => setShowIncidentGuide(true)}
                className="btn btn-secondary"
                style={{ flex: 1, fontSize: '11.5px', padding: '6px 8px', color: 'var(--amber)' }}
              >
                Link Par Click Ho Gaya?
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
            <span>Kisi bhi Number, Link, UPI ya Message ko yahan check karein:</span>
          </label>
          <button
            onClick={handlePaste}
            className="btn btn-secondary"
            style={{ padding: '6px 12px', fontSize: '12px' }}
            title="Clipboard se paste karein"
          >
            📋 Clipboard se Paste karein
          </button>
        </div>

        <div style={{ position: 'relative' }}>
          <textarea
            className="input-field"
            rows={4}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Yahan type ya paste karein... Udaharan:
• Phone number: +91 98765 43210
• UPI ID: payment-officer@paytm
• Link: http://sbi-kyc-update.com/login
• Pura SMS ya WhatsApp message (jaise electricity bill cut, work from home task, lottery)"
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
            💡 Tip: Agar message me OTP ya card number hoga, hamara system use turant redact (chhupa) dega.
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
              {loading ? 'Checking...' : '🔍 Check Karein'}
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
                    {result.level === 'danger' ? 'KHATRA (DANGER)' : result.level === 'caution' ? 'SAVDHAAN (CAUTION)' : 'SURAKSHIT (SAFE)'}
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
              onClick={() => handleCopy(`${result.title}\n\n${result.summary}\n\nAction:\n${result.actions.join('\n')}`)}
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
              <span>Yeh Kya Hai? (Explanation)</span>
            </h4>
            <p style={{ color: '#e2e8f0', fontSize: '15px', lineHeight: 1.6, margin: 0 }}>
              {result.summary}
            </p>
          </div>

          {/* Action Steps: Ab Main Kya Karoon? */}
          <div style={{ marginBottom: '24px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 800, color: '#fff', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>👉</span>
              <span>Ab Aapko Kya Karna Chahiye? (Action Steps)</span>
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
                    🔒 Redacted Message Preview (Aapka OTP/Sensitve data chhupa diya gaya hai):
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
                    Khatre Ke Sanket (Threat Flags Found):
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
                  Kya paise cut gaye hain? Pareshan na hon!
                </div>
                <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                  Aap pehle 2 ghante ke andar 1930 par call karein. Bank transaction hold hone ke chances 85% tak badh jaate hain.
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

      {/* Common Scam Examples / Quick-Check Cards */}
      <div className="card" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '17px', fontWeight: 800, color: '#fff', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span>🔥</span>
          <span>India Me Aaj-Kal Chal Rahe Top Scams (Click Karke Check Karein)</span>
        </h3>
        <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', marginBottom: '16px' }}>
          Agar aapko inme se milta-julta koi message aaya hai, toh click karke dekhein hamara AI scanner use kaise pakadta hai:
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
          {sampleScenarios.map((sc, idx) => (
            <div
              key={idx}
              onClick={() => {
                setQuery(sc.text);
                handleScan(sc.text);
              }}
              style={{
                background: 'var(--bg-card-alt)',
                border: '1px solid var(--border)',
                borderRadius: '10px',
                padding: '16px',
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--teal)';
                e.currentTarget.style.transform = 'translateY(-2px)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border)';
                e.currentTarget.style.transform = 'translateY(0)';
              }}
            >
              <div style={{ fontWeight: 700, fontSize: '14px', color: '#fff', marginBottom: '6px' }}>
                {sc.title}
              </div>
              <div style={{ color: 'var(--text-muted)', fontSize: '12px', lineHeight: 1.5, overflow: 'hidden', textOverflow: 'ellipsis', display: '-webkit-box', WebkitLineClamp: 3, WebkitBoxOrient: 'vertical' }}>
                "{sc.text}"
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--teal)', fontSize: '12px', fontWeight: 600, marginTop: '10px' }}>
                <span>Try this sample</span>
                <ArrowRight size={13} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 4 Golden Rules for Every Indian Citizen */}
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
          <span>4 Golden Rules: Kabhi Koi Aapko Thag Nahi Sakta</span>
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px' }}>
          <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '18px', marginBottom: '6px' }}>🔑 1. Paise lene ke liye PIN nahi lagta</div>
            <p style={{ color: 'var(--text-muted)', fontSize: '12.5px', lineHeight: 1.5, margin: 0 }}>
              Agar koi kahe ki "Mai aapko paise bhej raha hoon, QR code scan karke UPI PIN enter karo", toh samajh jaiye 100% fraud hai. PIN sirf paise bhejne ke liye hota hai!
            </p>
          </div>

          <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '18px', marginBottom: '6px' }}>👮 2. "Digital Arrest" jaisa koi kanoon nahi</div>
            <p style={{ color: 'var(--text-muted)', fontSize: '12.5px', lineHeight: 1.5, margin: 0 }}>
              Police, CBI, ya Customs kabhi WhatsApp video call ya Skype par kisi ko arrest nahi karti aur na hi bank account me paise transfer karne ko bolti hai. Turant call cut karein.
            </p>
          </div>

          <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '18px', marginBottom: '6px' }}>📲 3. Unknown APK Download Mat Karein</div>
            <p style={{ color: 'var(--text-muted)', fontSize: '12.5px', lineHeight: 1.5, margin: 0 }}>
              WhatsApp par aayi `.apk` file (jaise PM Yojana, Free Recharge, Wedding Card invite) download na karein. Yeh phone ka sara SMS aur OTP hack kar leti hai.
            </p>
          </div>

          <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '10px', border: '1px solid var(--border)' }}>
            <div style={{ fontSize: '18px', marginBottom: '6px' }}>⏳ 4. 2-Hour Golden Window (1930)</div>
            <p style={{ color: 'var(--text-muted)', fontSize: '12.5px', lineHeight: 1.5, margin: 0 }}>
              Agar kabhi galti se paise cut jayein, bina sharmaye turant 1930 par call karein aur cybercrime.gov.in par complaint darj karein taaki paisa freeze ho sake.
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
                <h3 style={{ fontSize: '18px', fontWeight: 800 }}>National Cyber Helpline 1930 Guide</h3>
              </div>
              <button onClick={() => setShowHelplineGuide(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '18px' }}>
                ✕
              </button>
            </div>

            <div style={{ fontSize: '14px', lineHeight: 1.6, color: '#e2e8f0', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <p>
                <b>1930</b> Bharat Sarkar (Ministry of Home Affairs - I4C) ka official toll-free national cybercrime helpline number hai jo financial cyber frauds ko rokne ke liye banaya gaya hai.
              </p>

              <div style={{ background: 'rgba(239, 68, 68, 0.1)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
                <b>Call karne se pehle yeh details paas rakhein:</b>
                <ul style={{ margin: '8px 0 0 18px', padding: 0, fontSize: '13px' }}>
                  <li>Aapka Bank Account Number aur IFSC</li>
                  <li>Jitne paise kate (Exact Amount) aur Time</li>
                  <li>UPI UTR / Reference ID (SMS ya Bank statement me hoti hai)</li>
                  <li>Fraudster ka Phone number, UPI ID ya Bank Account details</li>
                </ul>
              </div>

              <p>
                Jab aap 1930 par call karte hain, toh officer aapki complaint Citizen Financial Cyber Fraud Management System (CFCFRMS) me enter karta hai, jisse bank turant criminal ke account me paise hold/freeze kar deta hai.
              </p>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '8px' }}>
                <a
                  href="https://cybercrime.gov.in"
                  target="_blank"
                  rel="noreferrer"
                  className="btn btn-secondary"
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}
                >
                  <span>cybercrime.gov.in Kholein</span>
                  <ExternalLink size={13} />
                </a>
                <button className="btn btn-primary" onClick={() => setShowHelplineGuide(false)}>
                  Samajh Gaya (Close)
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
                <h3 style={{ fontSize: '18px', fontWeight: 800 }}>Galti Se Kisi Fraud Link Par Click Ho Gaya?</h3>
              </div>
              <button onClick={() => setShowIncidentGuide(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '18px' }}>
                ✕
              </button>
            </div>

            <div style={{ fontSize: '14px', lineHeight: 1.6, color: '#e2e8f0', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ padding: '10px 14px', borderRadius: '8px', background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', color: '#fcd34d' }}>
                Ghabraiye mat! Sirf link kholne se jab tak aapne koi form nahi bhara ya file download nahi ki, aap 90% safe hain. Niche diye gaye kadam turant uthayein:
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div style={{ padding: '10px', background: 'var(--bg-card)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <b>1. Browser Tab Turant Band Karein:</b> Koi bhi details (Aadhaar, Password, OTP) type na karein.
                </div>
                <div style={{ padding: '10px', background: 'var(--bg-card)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <b>2. Koi File Download Hui Kya?</b> Phone ke "Downloads" folder me check karein. Agar koi `.apk` ya `.zip` file download hui hai toh use bina open kiye DELETE karein.
                </div>
                <div style={{ padding: '10px', background: 'var(--bg-card)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <b>3. Agar Password Enter Kar Diya Hai:</b> Turant us website/bank ka password change karein aur 2-Factor Authentication on karein.
                </div>
                <div style={{ padding: '10px', background: 'var(--bg-card)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <b>4. Bank App Me Debit/Credit Card Freeze Karein:</b> Agar card details dali thi, toh apne official bank app me jaakar card turant lock/freeze karein.
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

