import React, { useState } from 'react';
import { Phone, CreditCard, ShieldAlert, KeyRound, AlertTriangle, CheckCircle, PlusCircle } from 'lucide-react';
import { checkPhone, checkUpi, addScamReport, checkPasswordBreach } from '../api';
import { ScamCheckResult, BreachResult } from '../types';

export const ScamLookup: React.FC = () => {
  // Phone check state
  const [phoneInput, setPhoneInput] = useState<string>('');
  const [phoneResult, setPhoneResult] = useState<ScamCheckResult | null>(null);
  const [loadingPhone, setLoadingPhone] = useState<boolean>(false);

  // UPI check state
  const [upiInput, setUpiInput] = useState<string>('');
  const [upiResult, setUpiResult] = useState<ScamCheckResult | null>(null);
  const [loadingUpi, setLoadingUpi] = useState<boolean>(false);

  // Password breach state
  const [passwordInput, setPasswordInput] = useState<string>('');
  const [breachResult, setBreachResult] = useState<BreachResult | null>(null);
  const [loadingBreach, setLoadingBreach] = useState<boolean>(false);

  // New report modal state
  const [showReportModal, setShowReportModal] = useState<boolean>(false);
  const [repType, setRepType] = useState<string>('phone');
  const [repValue, setRepValue] = useState<string>('');
  const [repCategory, setRepCategory] = useState<string>('bank_fraud');
  const [repNote, setRepNote] = useState<string>('');
  const [submittingRep, setSubmittingRep] = useState<boolean>(false);

  const handleCheckPhone = async () => {
    if (!phoneInput.trim()) return;
    setLoadingPhone(true);
    setPhoneResult(null);
    try {
      const res = await checkPhone(phoneInput.trim());
      setPhoneResult(res);
    } catch (err: any) {
      alert(`Phone check failed: ${err.message}`);
    } finally {
      setLoadingPhone(false);
    }
  };

  const handleCheckUpi = async () => {
    if (!upiInput.trim()) return;
    setLoadingUpi(true);
    setUpiResult(null);
    try {
      const res = await checkUpi(upiInput.trim());
      setUpiResult(res);
    } catch (err: any) {
      alert(`UPI check failed: ${err.message}`);
    } finally {
      setLoadingUpi(false);
    }
  };

  const handleCheckPassword = async () => {
    if (!passwordInput.trim()) return;
    setLoadingBreach(true);
    setBreachResult(null);
    try {
      const res = await checkPasswordBreach(passwordInput);
      setBreachResult(res);
    } catch (err: any) {
      alert(`Password check failed: ${err.message}`);
    } finally {
      setLoadingBreach(false);
    }
  };

  const handleSubmitReport = async () => {
    if (!repValue.trim()) return;
    setSubmittingRep(true);
    try {
      await addScamReport(repType, repValue.trim(), repCategory, repNote.trim());
      alert('Report recorded in the threat database.');
      setShowReportModal(false);
      setRepValue('');
      setRepNote('');
    } catch (err: any) {
      alert(`Submission failed: ${err.message}`);
    } finally {
      setSubmittingRep(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={22} color="var(--amber)" /> Scam Intelligence & Breach Verification
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '13.5px' }}>
              Query reported fraudulent phone numbers, malicious UPI payment addresses, and exposed passwords.
            </p>
          </div>
          <button className="btn btn-secondary" onClick={() => setShowReportModal(true)}>
            <PlusCircle size={16} /> Report New Threat
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
        {/* Card 1: Phone Scam Lookup */}
        <div className="card">
          <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Phone size={18} color="var(--teal)" /> Fraudulent Phone Number Lookup
          </h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '14px' }}>
            Checks phone numbers against known courier, electricity bill, KYC, or impersonation fraud lists.
          </p>

          <div style={{ display: 'flex', gap: '10px', marginBottom: '14px' }}>
            <input
              type="text"
              className="input-field"
              placeholder="e.g. +91 98765 43210"
              value={phoneInput}
              onChange={(e) => setPhoneInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCheckPhone()}
            />
            <button className="btn btn-primary" onClick={handleCheckPhone} disabled={loadingPhone || !phoneInput.trim()}>
              {loadingPhone ? 'Checking...' : 'Check'}
            </button>
          </div>

          {phoneResult && (
            <div style={{
              background: 'var(--bg-card-alt)', borderRadius: '8px', padding: '14px',
              border: `1px solid ${phoneResult.is_reported ? 'rgba(239, 68, 68, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`
            }}>
              {phoneResult.is_reported ? (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--red)', fontWeight: 700, marginBottom: '6px' }}>
                    <AlertTriangle size={16} /> REPORTED SCAM NUMBER
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--text-main)' }}>
                    Category: <b>{phoneResult.category || 'General Scam'}</b>
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '2px' }}>
                    Reports on record: {phoneResult.report_count}
                  </div>
                  {phoneResult.note && (
                    <div style={{ fontSize: '12.5px', color: 'var(--text-muted)', marginTop: '6px' }}>
                      Note: {phoneResult.note}
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--green)', fontSize: '13.5px' }}>
                  <CheckCircle size={18} /> No reports found in local threat database.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Card 2: UPI ID Lookup */}
        <div className="card">
          <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <CreditCard size={18} color="var(--cyan)" /> Scam UPI Payment VPA Lookup
          </h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '14px' }}>
            Verifies UPI handles against known phishing refund or fake lottery payment targets.
          </p>

          <div style={{ display: 'flex', gap: '10px', marginBottom: '14px' }}>
            <input
              type="text"
              className="input-field"
              placeholder="e.g. refund-care@okhdfcbank"
              value={upiInput}
              onChange={(e) => setUpiInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCheckUpi()}
            />
            <button className="btn btn-primary" onClick={handleCheckUpi} disabled={loadingUpi || !upiInput.trim()}>
              {loadingUpi ? 'Checking...' : 'Check'}
            </button>
          </div>

          {upiResult && (
            <div style={{
              background: 'var(--bg-card-alt)', borderRadius: '8px', padding: '14px',
              border: `1px solid ${upiResult.is_reported ? 'rgba(239, 68, 68, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`
            }}>
              {upiResult.is_reported ? (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--red)', fontWeight: 700, marginBottom: '6px' }}>
                    <AlertTriangle size={16} /> REPORTED FRAUDULENT VPA
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--text-main)' }}>
                    Category: <b>{upiResult.category || 'Payment Fraud'}</b>
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '2px' }}>
                    Reports: {upiResult.report_count}
                  </div>
                  {upiResult.note && (
                    <div style={{ fontSize: '12.5px', color: 'var(--text-muted)', marginTop: '6px' }}>
                      Note: {upiResult.note}
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--green)', fontSize: '13.5px' }}>
                  <CheckCircle size={18} /> No reports found in local threat database.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Card 3: Password Breach Checker */}
        <div className="card">
          <h3 style={{ fontSize: '16px', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <KeyRound size={18} color="var(--blue)" /> Password Data Breach Check
          </h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '14px' }}>
            Uses <b>k-anonymity</b> via HaveIBeenPwned. Your password is never sent over the network (only 5 SHA-1 hash chars).
          </p>

          <div style={{ display: 'flex', gap: '10px', marginBottom: '14px' }}>
            <input
              type="password"
              className="input-field"
              placeholder="Test a password against leaked credentials"
              value={passwordInput}
              onChange={(e) => setPasswordInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCheckPassword()}
            />
            <button className="btn btn-primary" onClick={handleCheckPassword} disabled={loadingBreach || !passwordInput.trim()}>
              {loadingBreach ? 'Checking...' : 'Check'}
            </button>
          </div>

          {breachResult && (
            <div style={{
              background: 'var(--bg-card-alt)', borderRadius: '8px', padding: '14px',
              border: `1px solid ${breachResult.pwned ? 'rgba(239, 68, 68, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`
            }}>
              {breachResult.pwned ? (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--red)', fontWeight: 700, marginBottom: '4px' }}>
                    <AlertTriangle size={16} /> PASSWORD EXPOSED IN BREACHES
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--text-main)' }}>
                    This password has appeared in <b>{breachResult.count.toLocaleString()}</b> data breaches. Do NOT use it.
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--green)', fontSize: '13.5px' }}>
                  <CheckCircle size={18} /> Password not found in known database breaches.
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Report Modal */}
      {showReportModal && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100
        }}>
          <div className="card" style={{ width: '480px', maxWidth: '90%' }}>
            <h3 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '14px' }}>Submit Threat Report</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <label style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>Threat Type</label>
                <select
                  className="input-field"
                  value={repType}
                  onChange={(e) => setRepType(e.target.value)}
                >
                  <option value="phone">Phone Number</option>
                  <option value="upi">UPI ID (VPA)</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>Target Value</label>
                <input
                  type="text"
                  className="input-field"
                  placeholder={repType === 'phone' ? '9876543210' : 'fraud@upi'}
                  value={repValue}
                  onChange={(e) => setRepValue(e.target.value)}
                />
              </div>

              <div>
                <label style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>Scam Category</label>
                <select
                  className="input-field"
                  value={repCategory}
                  onChange={(e) => setRepCategory(e.target.value)}
                >
                  <option value="bank_fraud">Bank / KYC Fraud</option>
                  <option value="courier_scam">Courier / Customs Scam</option>
                  <option value="lottery_scam">Fake Lottery / Prize</option>
                  <option value="job_scam">Fake Part-Time Job Scam</option>
                  <option value="digital_arrest">Digital Arrest Impersonation</option>
                  <option value="loan_scam">Fake Loan App</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>Note / Details</label>
                <textarea
                  className="textarea-field"
                  rows={3}
                  placeholder="Additional context or impersonated entity"
                  value={repNote}
                  onChange={(e) => setRepNote(e.target.value)}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
                <button className="btn btn-secondary" onClick={() => setShowReportModal(false)}>Cancel</button>
                <button className="btn btn-primary" onClick={handleSubmitReport} disabled={submittingRep || !repValue.trim()}>
                  {submittingRep ? 'Submitting...' : 'Save Report'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

