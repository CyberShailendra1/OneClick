import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { HomePage } from './components/HomePage';
import { CitizenShield } from './components/CitizenShield';
import { SingleScan } from './components/SingleScan';
import { BatchScan } from './components/BatchScan';
import { History } from './components/History';
import { PhishingScanner } from './components/PhishingScanner';
import { OtpGuard } from './components/OtpGuard';
import { ScamLookup } from './components/ScamLookup';
import { SecurityTools } from './components/SecurityTools';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('home');
  const [vtApiKey, setVtApiKey] = useState<string>(() => {
    return localStorage.getItem('oneclick_vt_key') || '';
  });

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        vtApiKey={vtApiKey}
        setVtApiKey={setVtApiKey}
      />

      <main style={{ flex: 1, maxWidth: '1400px', width: '100%', margin: '0 auto', padding: '28px 24px' }}>
        {activeTab === 'home' && <HomePage onNavigate={setActiveTab} />}
        {activeTab === 'shield' && <CitizenShield vtApiKey={vtApiKey} onNavigateToTab={setActiveTab} />}
        {activeTab === 'single' && <SingleScan vtApiKey={vtApiKey} />}
        {activeTab === 'batch' && <BatchScan vtApiKey={vtApiKey} />}
        {activeTab === 'history' && <History />}
        {activeTab === 'phishing' && <PhishingScanner vtApiKey={vtApiKey} />}
        {activeTab === 'otp' && <OtpGuard />}
        {activeTab === 'scam' && <ScamLookup />}
        {activeTab === 'tools' && <SecurityTools vtApiKey={vtApiKey} />}
      </main>


      <footer style={{ borderTop: '1px solid var(--border)', padding: '20px 24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px', background: 'var(--bg-card)' }}>
        <div style={{ maxWidth: '1400px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <b>OneClick APK Analyzer</b> • Multi-layer Android malware & threat intelligence
          </div>
          <div style={{ display: 'flex', gap: '16px' }}>
            <span>FastAPI Backend: <code>http://localhost:8000</code></span>
            <span>React + TypeScript Web UI</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;

