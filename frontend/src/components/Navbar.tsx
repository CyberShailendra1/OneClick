import React, { useState, useEffect } from 'react';
import { Shield, Key, Activity, CheckCircle, AlertTriangle, ExternalLink, X, User } from 'lucide-react';
import { checkHealth, fetchCurrentUser } from '../api';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  vtApiKey: string;
  setVtApiKey: (key: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  vtApiKey,
  setVtApiKey,
}) => {
  const [isHealthy, setIsHealthy] = useState<boolean | null>(null);
  const [showKeyModal, setShowKeyModal] = useState<boolean>(false);
  const [tempKey, setTempKey] = useState<string>(vtApiKey);

  useEffect(() => {
    checkHealth()
      .then(() => setIsHealthy(true))
      .catch(() => setIsHealthy(false));

    const interval = setInterval(() => {
      checkHealth()
        .then(() => setIsHealthy(true))
        .catch(() => setIsHealthy(false));
    }, 15000);

    return () => clearInterval(interval);
  }, []);

  const handleSaveKey = () => {
    setVtApiKey(tempKey);
    localStorage.setItem('oneclick_vt_key', tempKey);
    setShowKeyModal(false);
  };

  const [currentUser, setCurrentUser] = useState<{ phone: string } | null>(null);

  useEffect(() => {
    const token = localStorage.getItem('oneclick_user_token');
    if (token) {
      fetchCurrentUser(token)
        .then((res) => setCurrentUser(res.user))
        .catch(() => setCurrentUser(null));
    } else {
      setCurrentUser(null);
    }
  }, [activeTab]);

  return (
    <header style={{ borderBottom: '1px solid var(--border)', background: 'rgba(16, 23, 38, 0.95)', backdropFilter: 'blur(12px)', position: 'sticky', top: 0, zIndex: 50, width: '100%' }}>
      <div style={{ width: '100%', margin: '0 auto', padding: '0 28px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: '68px' }}>
          {/* Logo */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }} onClick={() => setActiveTab('home')}>


            <div style={{
              width: '40px', height: '40px', borderRadius: '10px',
              background: 'linear-gradient(135deg, rgba(20, 184, 166, 0.2), rgba(6, 182, 212, 0.2))',
              border: '1px solid rgba(20, 184, 166, 0.4)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 15px rgba(20, 184, 166, 0.2)'
            }}>
              <Shield size={24} color="var(--teal)" />
            </div>
            <div>
              <div style={{ fontWeight: 800, fontSize: '18px', letterSpacing: '0.5px', color: '#fff' }}>
                ONECLICK
              </div>
              <div style={{ fontSize: '11px', color: 'var(--cyan)', fontWeight: 600, letterSpacing: '1px' }}>
                MALWARE & THREAT DEFENSE
              </div>
            </div>
          </div>

          {/* Center / Home Quick Link */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              onClick={() => setActiveTab('home')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '6px 14px',
                borderRadius: '8px',
                border: '1px solid var(--border)',
                background: activeTab === 'home' ? 'var(--bg-card-alt)' : 'transparent',
                color: activeTab === 'home' ? 'var(--teal)' : 'var(--text-muted)',
                fontWeight: activeTab === 'home' ? 700 : 500,
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
            >
              <span>🏠</span>
              <span>Overview & Services</span>
            </button>
          </div>

          {/* Right Status & VT Key */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            {/* Health pill */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px',
              padding: '4px 10px', borderRadius: '999px',
              background: isHealthy ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
              color: isHealthy ? 'var(--green)' : 'var(--red)',
              border: `1px solid ${isHealthy ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
            }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: isHealthy ? 'var(--green)' : 'var(--red)' }} />
              <span>{isHealthy === null ? 'Connecting...' : isHealthy ? 'API Online' : 'API Offline'}</span>
            </div>

            {/* VT Key Button */}
            <button
              onClick={() => { setTempKey(vtApiKey); setShowKeyModal(true); }}
              className="btn btn-secondary"
              style={{ padding: '6px 12px', fontSize: '13px' }}
              title="VirusTotal API Key"
            >
              <Key size={15} color={vtApiKey ? 'var(--teal)' : 'var(--text-muted)'} />
              <span>{vtApiKey ? 'VT Key Set' : 'Add VT Key'}</span>
            </button>

            {/* Optional Citizen Auth Button */}
            <button
              onClick={() => setActiveTab('dashboard')}
              className={currentUser ? 'btn btn-secondary' : 'btn btn-primary'}
              style={{
                padding: '6px 12px',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                borderColor: currentUser ? 'rgba(20, 184, 166, 0.4)' : undefined
              }}
              title={currentUser ? `Logged in: +91 ${currentUser.phone}` : 'Optional Citizen Login'}
            >
              <User size={15} color={currentUser ? 'var(--teal)' : '#fff'} />
              <span>{currentUser ? `+91 ${currentUser.phone}` : 'Sign In'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* VT Key Modal */}
      {showKeyModal && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100
        }}>
          <div className="card" style={{ width: '480px', maxWidth: '90%' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Key size={20} color="var(--teal)" />
                <h3 style={{ fontSize: '18px', fontWeight: 700 }}>VirusTotal API Key</h3>
              </div>
              <button onClick={() => setShowKeyModal(false)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X size={20} />
              </button>
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '14px', lineHeight: 1.5 }}>
              A free VirusTotal API key allows OneClick to query global threat intelligence engines for hash lookups and URL analysis.
            </p>
            <input
              type="password"
              className="input-field"
              placeholder="Paste your 64-character VirusTotal API Key"
              value={tempKey}
              onChange={(e) => setTempKey(e.target.value)}
              style={{ marginBottom: '16px' }}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <a
                href="https://www.virustotal.com/gui/join-us"
                target="_blank"
                rel="noreferrer"
                style={{ color: 'var(--cyan)', fontSize: '12.5px', display: 'flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}
              >
                Get a free key <ExternalLink size={12} />
              </a>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button className="btn btn-secondary" onClick={() => setShowKeyModal(false)}>Cancel</button>
                <button className="btn btn-primary" onClick={handleSaveKey}>Save Key</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};

