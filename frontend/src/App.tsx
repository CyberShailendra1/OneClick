import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';
import { HomePage } from './components/HomePage';
import { CitizenShield } from './components/CitizenShield';
import { SingleScan } from './components/SingleScan';
import { BatchScan } from './components/BatchScan';
import { History } from './components/History';
import { PhishingScanner } from './components/PhishingScanner';
import { OtpGuard } from './components/OtpGuard';
import { ScamLookup } from './components/ScamLookup';
import { SecurityTools } from './components/SecurityTools';
import { UserDashboard } from './components/UserDashboard';

export const App: React.FC = () => {
  // Map between URL paths and tab IDs
  const pathToTab = (pathname: string): string => {
    const clean = pathname.replace(/^\/+|\/+$/g, '').toLowerCase();
    const validTabs = ['home', 'shield', 'single', 'batch', 'history', 'phishing', 'otp', 'scam', 'tools', 'dashboard'];
    if (clean === '' || clean === 'home') return 'home';
    if (clean === 'apk' || clean === 'apk-scanner') return 'single';
    if (clean === 'smart-shield') return 'shield';
    if (clean === 'login' || clean === 'auth' || clean === 'user') return 'dashboard';
    if (validTabs.includes(clean)) return clean;
    return 'home';
  };

  const tabToPath = (tabId: string): string => {
    if (tabId === 'home') return '/';
    return `/${tabId}`;
  };

  const [activeTab, setActiveTabState] = useState<string>(() => {
    return pathToTab(window.location.pathname);
  });

  const [vtApiKey, setVtApiKey] = useState<string>(() => {
    return localStorage.getItem('oneclick_vt_key') || '';
  });

  // Navigate function that also updates browser URL path
  const handleNavigate = (tabId: string) => {
    setActiveTabState(tabId);
    const targetPath = tabToPath(tabId);
    if (window.location.pathname !== targetPath) {
      window.history.pushState({ tabId }, '', targetPath);
    }
  };

  // Listen to browser Back / Forward buttons
  React.useEffect(() => {
    const handlePopState = () => {
      setActiveTabState(pathToTab(window.location.pathname));
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Navbar
        activeTab={activeTab}
        setActiveTab={handleNavigate}
        vtApiKey={vtApiKey}
        setVtApiKey={setVtApiKey}
      />

      <div style={{ display: 'flex', flex: 1, minHeight: 'calc(100vh - 68px)' }}>
        <Sidebar activeTab={activeTab} setActiveTab={handleNavigate} />

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, overflowX: 'hidden' }}>
          <main style={{ flex: 1, width: '100%', maxWidth: '1300px', margin: '0 auto', padding: '28px 28px' }}>
            {activeTab === 'home' && <HomePage onNavigate={handleNavigate} />}
            {activeTab === 'shield' && <CitizenShield vtApiKey={vtApiKey} onNavigateToTab={handleNavigate} />}
            {activeTab === 'single' && <SingleScan vtApiKey={vtApiKey} />}
            {activeTab === 'batch' && <BatchScan vtApiKey={vtApiKey} />}
            {activeTab === 'history' && <History />}
            {activeTab === 'phishing' && <PhishingScanner vtApiKey={vtApiKey} />}
            {activeTab === 'otp' && <OtpGuard />}
            {activeTab === 'scam' && <ScamLookup />}
            {activeTab === 'tools' && <SecurityTools vtApiKey={vtApiKey} />}
            {activeTab === 'dashboard' && <UserDashboard onNavigateToTab={handleNavigate} />}
          </main>

          <footer style={{ borderTop: '1px solid var(--border)', padding: '20px 28px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px', background: 'var(--bg-card)', marginTop: 'auto' }}>
            <div style={{ maxWidth: '1300px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
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
      </div>
    </div>
  );
};

export default App;

