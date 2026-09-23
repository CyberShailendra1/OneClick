import React from 'react';
import { Shield, Sparkles, AlertCircle } from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isCollapsed?: boolean;
  setIsCollapsed?: (collapsed: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
}) => {
  const navSections = [
    {
      heading: 'Citizen Protection',
      items: [
        { id: 'shield', label: 'Smart Shield', icon: '🛡️', badge: 'Live AI' },
        { id: 'phishing', label: 'Phishing & URLs', icon: '🎣' },
        { id: 'otp', label: 'OTP Guard', icon: '🔒' },
        { id: 'scam', label: 'Scam & Breach', icon: '📞' },
      ]
    },
    {
      heading: 'Malware & Forensics',
      items: [
        { id: 'single', label: 'APK Scanner', icon: '🔍' },
        { id: 'batch', label: 'Batch Scan', icon: '📦' },
        { id: 'history', label: 'Scan History', icon: '🕓' },
      ]
    },
    {
      heading: 'Diagnostics & Suite',
      items: [
        { id: 'tools', label: 'Security Tools', icon: '🛠️' },
      ]
    }
  ];

  return (
    <aside
      style={{
        width: '260px',
        minWidth: '260px',
        height: 'calc(100vh - 68px)',
        position: 'sticky',
        top: '68px',
        background: 'rgba(13, 20, 36, 0.95)',
        backdropFilter: 'blur(16px)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        zIndex: 40,
        overflowY: 'auto',
      }}
    >
      <div style={{ padding: '20px 14px' }}>
        {/* Quick Citizen Shield Hero Pill */}
        <div
          onClick={() => setActiveTab('shield')}
          style={{
            padding: '12px 14px',
            borderRadius: '12px',
            background: activeTab === 'shield'
              ? 'linear-gradient(135deg, rgba(20, 184, 166, 0.25), rgba(6, 182, 212, 0.2))'
              : 'rgba(20, 184, 166, 0.08)',
            border: activeTab === 'shield' ? '1px solid var(--teal)' : '1px solid rgba(20, 184, 166, 0.25)',
            marginBottom: '20px',
            cursor: 'pointer',
            transition: 'all 0.2s',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
          }}
        >
          <div
            style={{
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              background: 'rgba(20, 184, 166, 0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '18px',
            }}
          >
            🛡️
          </div>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#fff' }}>Smart Shield</div>
            <div style={{ fontSize: '11px', color: 'var(--teal)' }}>Universal Instant Analysis</div>
          </div>
        </div>

        {/* Navigation Sections */}
        {navSections.map((section, idx) => (
          <div key={idx} style={{ marginBottom: '18px' }}>
            <div
              style={{
                fontSize: '11px',
                fontWeight: 700,
                color: 'var(--text-muted)',
                letterSpacing: '0.8px',
                textTransform: 'uppercase',
                padding: '0 10px 8px 10px',
              }}
            >
              {section.heading}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
              {section.items.map((item) => {
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveTab(item.id)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '10px 12px',
                      borderRadius: '10px',
                      border: 'none',
                      background: isActive ? 'rgba(20, 184, 166, 0.14)' : 'transparent',
                      color: isActive ? 'var(--teal)' : 'var(--text-muted)',
                      fontWeight: isActive ? 700 : 500,
                      fontSize: '13.5px',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.15s ease-in-out',
                      outline: 'none',
                      borderLeft: isActive ? '3px solid var(--teal)' : '3px solid transparent',
                    }}
                    onMouseEnter={(e) => {
                      if (!isActive) {
                        e.currentTarget.style.background = 'rgba(255, 255, 255, 0.04)';
                        e.currentTarget.style.color = '#fff';
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (!isActive) {
                        e.currentTarget.style.background = 'transparent';
                        e.currentTarget.style.color = 'var(--text-muted)';
                      }
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{ fontSize: '16px' }}>{item.icon}</span>
                      <span>{item.label}</span>
                    </div>

                    {item.badge && (
                      <span
                        style={{
                          fontSize: '10px',
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: '6px',
                          background: item.badge === 'Live AI' ? 'rgba(20, 184, 166, 0.2)' : 'rgba(255, 255, 255, 0.08)',
                          color: item.badge === 'Live AI' ? 'var(--teal)' : 'var(--text-muted)',
                        }}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Emergency Helpline Footer in Sidebar */}
      <div
        style={{
          padding: '14px',
          margin: '12px',
          background: 'rgba(239, 68, 68, 0.08)',
          border: '1px solid rgba(239, 68, 68, 0.2)',
          borderRadius: '12px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11.5px', color: 'var(--red)', fontWeight: 700 }}>
          <AlertCircle size={14} /> Cyber Fraud Helpline
        </div>
        <div style={{ fontSize: '17px', fontWeight: 800, color: '#fff', marginTop: '4px', letterSpacing: '0.5px' }}>
          📞 Dial 1930
        </div>
        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
          National Cybercrime Reporting Portal (MHA)
        </div>
      </div>
    </aside>
  );
};

