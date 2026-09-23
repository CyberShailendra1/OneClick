import React, { useState, useEffect } from 'react';
import { User, Phone, KeyRound, LogOut, CheckCircle, ShieldCheck, Clock, FileText, ArrowRight, AlertCircle, Sparkles } from 'lucide-react';
import { sendAuthOtp, verifyAuthOtp, fetchCurrentUser, logoutUser, getHistory, getUrlHistory } from '../api';
import { HistoryRecord, UrlHistoryRecord } from '../types';

interface UserDashboardProps {
  onNavigateToTab?: (tab: string) => void;
}

export const UserDashboard: React.FC<UserDashboardProps> = ({ onNavigateToTab }) => {
  const [token, setToken] = useState<string>(() => localStorage.getItem('oneclick_user_token') || '');
  const [user, setUser] = useState<{ id: number; phone: string; created_at: string } | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [phoneInput, setPhoneInput] = useState<string>('');
  const [otpInput, setOtpInput] = useState<string>('');
  const [step, setStep] = useState<'phone' | 'otp'>('phone');
  const [errorMsg, setErrorMsg] = useState<string>('');
  const [successMsg, setSuccessMsg] = useState<string>('');
  const [demoOtpNotice, setDemoOtpNotice] = useState<string>('');

  // User scan history stats
  const [apkHistory, setApkHistory] = useState<HistoryRecord[]>([]);
  const [urlHistory, setUrlHistory] = useState<UrlHistoryRecord[]>([]);

  // Check existing session
  useEffect(() => {
    if (token) {
      setLoading(true);
      fetchCurrentUser(token)
        .then((res) => {
          setUser(res.user);
          loadUserStats();
        })
        .catch(() => {
          // Token expired or invalid
          localStorage.removeItem('oneclick_user_token');
          setToken('');
          setUser(null);
        })
        .finally(() => setLoading(false));
    }
  }, [token]);

  const loadUserStats = () => {
    getHistory(5).then(setApkHistory).catch(() => {});
    getUrlHistory(5).then(setUrlHistory).catch(() => {});
  };

  const handleSendOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');
    setDemoOtpNotice('');

    const cleanPhone = phoneInput.replace(/[^0-9]/g, '');
    if (cleanPhone.length < 10) {
      setErrorMsg('Please enter a valid 10-digit mobile number.');
      return;
    }

    setLoading(true);
    try {
      const res = await sendAuthOtp(cleanPhone);
      setStep('otp');
      setSuccessMsg(res.message);
      if (res.demo_otp) {
        setDemoOtpNotice(res.demo_otp);
        setOtpInput(res.demo_otp); // Pre-fill for instant frictionless demo experience
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to send OTP. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');

    if (!otpInput || otpInput.trim().length !== 6) {
      setErrorMsg('Please enter the 6-digit OTP code.');
      return;
    }

    setLoading(true);
    try {
      const cleanPhone = phoneInput.replace(/[^0-9]/g, '');
      const res = await verifyAuthOtp(cleanPhone, otpInput.trim());
      localStorage.setItem('oneclick_user_token', res.token);
      setToken(res.token);
      setStep('phone');
      setPhoneInput('');
      setOtpInput('');
      setDemoOtpNotice('');
    } catch (err: any) {
      setErrorMsg(err.message || 'Invalid or expired OTP code.');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    if (token) {
      await logoutUser(token).catch(() => {});
    }
    localStorage.removeItem('oneclick_user_token');
    setToken('');
    setUser(null);
    setStep('phone');
    setErrorMsg('');
    setSuccessMsg('');
  };

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Header Banner */}
      <div
        style={{
          background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8))',
          border: '1px solid var(--border)',
          borderRadius: '16px',
          padding: '28px 32px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '20px',
        }}
      >
        <div>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '4px 12px', background: 'rgba(20, 184, 166, 0.1)', border: '1px solid rgba(20, 184, 166, 0.25)', borderRadius: '999px', fontSize: '12px', color: 'var(--teal)', fontWeight: 600, marginBottom: '12px' }}>
            <Sparkles size={14} /> Optional User Portal
          </div>
          <h1 style={{ fontSize: '26px', fontWeight: 800, color: '#fff', marginBottom: '6px' }}>
            Citizen Security Dashboard
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '14px', maxWidth: '600px', lineHeight: 1.5 }}>
            Access is completely free and optional. Guest users can scan APKs and phishing links anytime without logging in. Logging in with your mobile OTP lets you review personal scan history and audit records.
          </p>
        </div>

        {user && (
          <button
            onClick={handleLogout}
            className="btn btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '8px', borderColor: 'rgba(239, 68, 68, 0.3)', color: 'var(--red)' }}
          >
            <LogOut size={16} /> Sign Out
          </button>
        )}
      </div>

      {/* Main Content: Logged In vs OTP Form */}
      {user ? (
        /* Logged In Dashboard View */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* User Profile Card */}
          <div className="card" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <div style={{ width: '56px', height: '56px', borderRadius: '14px', background: 'linear-gradient(135deg, rgba(20, 184, 166, 0.2), rgba(6, 182, 212, 0.2))', border: '1px solid rgba(20, 184, 166, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <User size={28} color="var(--teal)" />
              </div>
              <div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Verified Citizen Mobile</div>
                <div style={{ fontSize: '18px', fontWeight: 700, color: '#fff' }}>+91 {user.phone}</div>
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: 'var(--green)', marginTop: '2px' }}>
                  <ShieldCheck size={13} /> Active Session Verified
                </div>
              </div>
            </div>

            <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Account Created</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-main)', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Clock size={14} color="var(--cyan)" /> {new Date(user.created_at).toLocaleDateString()}
              </div>
            </div>

            <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Quick Actions</div>
              <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                <button
                  onClick={() => onNavigateToTab && onNavigateToTab('shield')}
                  className="btn btn-primary"
                  style={{ padding: '6px 14px', fontSize: '12.5px' }}
                >
                  Scan APK / URL
                </button>
                <button
                  onClick={() => onNavigateToTab && onNavigateToTab('history')}
                  className="btn btn-secondary"
                  style={{ padding: '6px 14px', fontSize: '12.5px' }}
                >
                  Full History
                </button>
              </div>
            </div>
          </div>

          {/* Recent Scans Overview */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '20px' }}>
            {/* Recent APK Scans */}
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h3 style={{ fontSize: '16px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <FileText size={18} color="var(--teal)" /> Recent APK Scans
                </h3>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{apkHistory.length} recorded</span>
              </div>

              {apkHistory.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '30px 20px', color: 'var(--text-muted)', fontSize: '13px' }}>
                  No APK files scanned yet in this session.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {apkHistory.slice(0, 4).map((rec, i) => (
                    <div
                      key={i}
                      style={{
                        padding: '12px 14px',
                        background: 'rgba(255,255,255,0.02)',
                        border: '1px solid var(--border)',
                        borderRadius: '10px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <div>
                        <div style={{ fontWeight: 600, fontSize: '13.5px', color: '#fff' }}>{rec.filename}</div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          Score: <span style={{ color: rec.risk_score > 60 ? 'var(--red)' : rec.risk_score > 30 ? 'var(--amber)' : 'var(--green)', fontWeight: 700 }}>{rec.risk_score}/100</span> • {rec.verdict}
                        </div>
                      </div>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{new Date(rec.scanned_at).toLocaleDateString()}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Recent URL / Phishing Checks */}
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h3 style={{ fontSize: '16px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldCheck size={18} color="var(--cyan)" /> Recent Phishing Checks
                </h3>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{urlHistory.length} recorded</span>
              </div>

              {urlHistory.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '30px 20px', color: 'var(--text-muted)', fontSize: '13px' }}>
                  No URLs checked yet in this session.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {urlHistory.slice(0, 4).map((rec, i) => (
                    <div
                      key={i}
                      style={{
                        padding: '12px 14px',
                        background: 'rgba(255,255,255,0.02)',
                        border: '1px solid var(--border)',
                        borderRadius: '10px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <div style={{ maxWidth: '75%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        <div style={{ fontWeight: 600, fontSize: '13.5px', color: '#fff', overflow: 'hidden', textOverflow: 'ellipsis' }}>{rec.url}</div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          Status: <span style={{ color: rec.verdict === 'MALICIOUS' ? 'var(--red)' : rec.verdict === 'SUSPICIOUS' ? 'var(--amber)' : 'var(--green)', fontWeight: 700 }}>{rec.verdict}</span>
                        </div>
                      </div>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{new Date(rec.scanned_at).toLocaleDateString()}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      ) : (
        /* OTP Login Card */
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '28px' }}>
          {/* Form */}
          <div className="card" style={{ padding: '32px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px' }}>
              <div style={{ width: '44px', height: '44px', borderRadius: '12px', background: 'rgba(20, 184, 166, 0.15)', border: '1px solid rgba(20, 184, 166, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <KeyRound size={22} color="var(--teal)" />
              </div>
              <div>
                <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#fff' }}>
                  {step === 'phone' ? 'Sign In with Mobile OTP' : 'Enter 6-Digit Code'}
                </h2>
                <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
                  {step === 'phone' ? 'No password required. Instant login via SMS OTP.' : `Enter the verification code sent to +91 ${phoneInput}`}
                </p>
              </div>
            </div>

            {errorMsg && (
              <div style={{ padding: '12px 14px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '8px', color: 'var(--red)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
                <AlertCircle size={16} /> {errorMsg}
              </div>
            )}

            {successMsg && (
              <div style={{ padding: '12px 14px', background: 'rgba(34, 197, 94, 0.1)', border: '1px solid rgba(34, 197, 94, 0.3)', borderRadius: '8px', color: 'var(--green)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
                <CheckCircle size={16} /> {successMsg}
              </div>
            )}

            {demoOtpNotice && (
              <div style={{ padding: '12px 16px', background: 'rgba(20, 184, 166, 0.12)', border: '1px solid rgba(20, 184, 166, 0.35)', borderRadius: '8px', color: 'var(--teal)', fontSize: '13px', marginBottom: '16px' }}>
                🔑 <b>Demo Test OTP:</b> <code>{demoOtpNotice}</code> (Auto-filled for local test)
              </div>
            )}

            {step === 'phone' ? (
              <form onSubmit={handleSendOtp} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px' }}>
                    10-Digit Mobile Number
                  </label>
                  <div style={{ position: 'relative' }}>
                    <div style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-muted)', fontSize: '14px', fontWeight: 600, borderRight: '1px solid var(--border)', paddingRight: '10px' }}>
                      <Phone size={16} /> +91
                    </div>
                    <input
                      type="tel"
                      className="input-field"
                      style={{ paddingLeft: '84px', fontSize: '15px', letterSpacing: '1px' }}
                      placeholder="9876543210"
                      maxLength={10}
                      value={phoneInput}
                      onChange={(e) => setPhoneInput(e.target.value)}
                      required
                      autoFocus
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={loading}
                  style={{ width: '100%', padding: '12px', fontSize: '14.5px', justifyContent: 'center', marginTop: '6px' }}
                >
                  {loading ? 'Sending OTP...' : 'Send Verification OTP'} <ArrowRight size={16} />
                </button>
              </form>
            ) : (
              <form onSubmit={handleVerifyOtp} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px' }}>
                    Enter 6-Digit Verification Code
                  </label>
                  <input
                    type="text"
                    className="input-field"
                    style={{ fontSize: '20px', letterSpacing: '6px', textAlign: 'center', fontWeight: 700 }}
                    placeholder="123456"
                    maxLength={6}
                    value={otpInput}
                    onChange={(e) => setOtpInput(e.target.value.replace(/[^0-9]/g, ''))}
                    required
                    autoFocus
                  />
                </div>

                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={loading}
                  style={{ width: '100%', padding: '12px', fontSize: '14.5px', justifyContent: 'center' }}
                >
                  {loading ? 'Verifying...' : 'Verify Code & Sign In'} <CheckCircle size={16} />
                </button>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
                  <button
                    type="button"
                    onClick={() => { setStep('phone'); setOtpInput(''); setErrorMsg(''); }}
                    style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '12.5px', cursor: 'pointer', padding: 0 }}
                  >
                    Change phone number
                  </button>
                  <button
                    type="button"
                    onClick={handleSendOtp}
                    disabled={loading}
                    style={{ background: 'none', border: 'none', color: 'var(--cyan)', fontSize: '12.5px', cursor: 'pointer', padding: 0, fontWeight: 600 }}
                  >
                    Resend code
                  </button>
                </div>
              </form>
            )}
          </div>

          {/* Benefits Info Box */}
          <div
            style={{
              background: 'rgba(255, 255, 255, 0.02)',
              border: '1px solid var(--border)',
              borderRadius: '16px',
              padding: '30px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#fff', marginBottom: '14px' }}>
                Why is Login Optional?
              </h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.6, marginBottom: '18px' }}>
                Cybersecurity tools should be barrier-free. When someone suspects an APK on their phone is malware or receives a suspicious SMS, every second counts.
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                  <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(34, 197, 94, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: '2px' }}>
                    <CheckCircle size={16} color="var(--green)" />
                  </div>
                  <div>
                    <div style={{ fontSize: '14px', fontWeight: 600, color: '#fff' }}>100% Free Guest Mode</div>
                    <div style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>Scan any APK, file, or URL immediately without entering any credentials.</div>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                  <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(20, 184, 166, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: '2px' }}>
                    <ShieldCheck size={16} color="var(--teal)" />
                  </div>
                  <div>
                    <div style={{ fontSize: '14px', fontWeight: 600, color: '#fff' }}>Saved Audit Trail</div>
                    <div style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>Logged in citizens retain their investigation history across sessions.</div>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                  <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(6, 182, 212, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: '2px' }}>
                    <KeyRound size={16} color="var(--cyan)" />
                  </div>
                  <div>
                    <div style={{ fontSize: '14px', fontWeight: 600, color: '#fff' }}>Zero Password Risk</div>
                    <div style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>One-time OTP verification means there are no user passwords stored to ever be breached.</div>
                  </div>
                </div>
              </div>
            </div>

            <div style={{ borderTop: '1px solid var(--border)', paddingTop: '16px', marginTop: '20px' }}>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Need instant analysis right now?{' '}
                <a
                  href="/shield"
                  onClick={(e) => { e.preventDefault(); onNavigateToTab && onNavigateToTab('shield'); }}
                  style={{ color: 'var(--teal)', fontWeight: 600, textDecoration: 'none' }}
                >
                  Go to Smart Shield →
                </a>
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
