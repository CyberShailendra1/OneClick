import React from 'react';
import {
  Shield,
  Smartphone,
  Globe,
  Lock,
  PhoneCall,
  Search,
  FileCheck,
  Server,
  Zap,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  ExternalLink,
  ChevronRight,
  Terminal,
  Activity,
  Award
} from 'lucide-react';

interface HomePageProps {
  onNavigate: (tabId: string) => void;
}

export const HomePage: React.FC<HomePageProps> = ({ onNavigate }) => {
  const tools = [
    {
      id: 'shield',
      icon: <Shield size={28} color="var(--teal)" />,
      badge: 'Bina Kisi Technical Knowledge Ke',
      title: 'Smart Shield (Universal AI Scam Detector)',
      desc: 'Kisi bhi anjaan Phone Number, UPI ID, Link ya SMS/WhatsApp message ko ek hi box me paste karke check karein. 1930 Helpline guide aur instant traffic-light verdict ke saath.',
      howItWorks: 'Auto-detect karta hai query ka type -> Phone/UPI fraud databases check karta hai -> Real-time phishing heuristics apply karta hai -> Hindi & English me seedha action plan batata hai.',
      whoUses: 'Aam Naagrik, Parivaar ke bade buzurg, WhatsApp & UPI users.',
      color: 'var(--teal)',
      bg: 'rgba(20, 184, 166, 0.08)',
      border: 'rgba(20, 184, 166, 0.25)',
    },
    {
      id: 'single',
      icon: <Smartphone size={28} color="var(--cyan)" />,
      badge: '3-Layer Deep Static Engine',
      title: 'Android APK Malware Scanner',
      desc: 'Khatarnak APK files (jaise WhatsApp par aane wale PM Yojana, Wedding Card, Bank Update APKs) ko bina install kiye deep scan karein.',
      howItWorks: 'Layer 1: SHA256 Hash query on VirusTotal. Layer 2: Decompile karke dangerous permissions aur hidden DEX loaders scan. Layer 3: AI Machine Learning risk scoring (0-100%).',
      whoUses: 'Android users, IT admins, mobile security researchers.',
      color: 'var(--cyan)',
      bg: 'rgba(6, 182, 212, 0.08)',
      border: 'rgba(6, 182, 212, 0.25)',
    },
    {
      id: 'phishing',
      icon: <Globe size={28} color="var(--amber)" />,
      badge: 'Anti-Phishing & Redirect Follower',
      title: 'Phishing & Fake Website Inspector',
      desc: 'Bank, Lottery ya KYC ke naam par aane wale links ko open kiye bina investigate karein ki yeh original hai ya nakli (typosquatting clone).',
      howItWorks: 'Levenshtein Distance se SBI/Paytm clone pakadta hai -> Domain Age (WHOIS) check karta hai -> Hidden password/card forms & iframe redirects inspect karta hai.',
      whoUses: 'Net banking users, online shoppers, fraud victims.',
      color: 'var(--amber)',
      bg: 'rgba(245, 158, 11, 0.08)',
      border: 'rgba(245, 158, 11, 0.25)',
    },
    {
      id: 'otp',
      icon: <Lock size={28} color="#a855f7" />,
      badge: 'Privacy & Token Masking',
      title: 'OTP Guard (Auto-Redaction)',
      desc: 'Kisi ko message ka screenshot ya text bhejte samay aapka 4-8 digit ka secret OTP aur verification code apne aap mask/hide ho jata hai.',
      howItWorks: 'High-speed Regex + keyword proximity scanner se OTPs/PINs ko detect karke `[REDACTED-OTP]` se replace karta hai taaki account safe rahe.',
      whoUses: 'Log jo support ya dosto ke saath SMS/error share karte hain.',
      color: '#a855f7',
      bg: 'rgba(168, 85, 247, 0.08)',
      border: 'rgba(168, 85, 247, 0.25)',
    },
    {
      id: 'scam',
      icon: <PhoneCall size={28} color="var(--red)" />,
      badge: 'Community Intel & Pwned Check',
      title: 'Scam DB & Password Breach Checker',
      desc: 'Frauds ke reported phone numbers aur UPI handles ki history check karein, aur k-Anonymity se dekhein ki aapka password leak toh nahi hua.',
      howItWorks: 'HaveIBeenPwned API (SHA1 first 5 chars k-Anonymity - safe & zero password disclosure) + Local SQLite crowdsourced scam database lookup.',
      whoUses: 'Har koi jise anjaan payment request ya suspicious call aayi ho.',
      color: 'var(--red)',
      bg: 'rgba(239, 68, 68, 0.08)',
      border: 'rgba(239, 68, 68, 0.25)',
    },
    {
      id: 'tools',
      icon: <Server size={28} color="#3b82f6" />,
      badge: 'Infra & Web Hardening Suite',
      title: 'Web & Infrastructure Security Tools',
      desc: 'Kisi bhi website ka Security Headers score, SSL/TLS certificate validity, DNS Email Spoofing (SPF/DMARC), aur Port Exposure scan karein.',
      howItWorks: 'HTTP response header auditing (HSTS, CSP), socket-level TLS cert chain analysis, DoH (DNS-over-HTTPS) SPF/DMARC inspection, aur socket connection port checks.',
      whoUses: 'Web developers, server owners, cybersecurity analysts.',
      color: '#3b82f6',
      bg: 'rgba(59, 130, 246, 0.08)',
      border: 'rgba(59, 130, 246, 0.25)',
    },
  ];

  const steps = [
    {
      step: '01',
      title: 'Input Paste Karein',
      desc: 'Aapko jo bhi suspicious laga — chahe anjaan phone number ho, UPI ID, link, koi message, ya koi file/APK — use simply paste ya upload karein.',
    },
    {
      step: '02',
      title: 'Multi-Engine Analysis',
      desc: 'OneClick ka backend bina kisi delay ke VirusTotal, Androguard static heuristics, Scam DB, aur AI model se test run karta hai.',
    },
    {
      step: '03',
      title: 'Seedha Verdict (Traffic Light)',
      desc: 'Aapko bina technical bhasha ke 🟢 Safe, 🟡 Caution, ya 🔴 Danger ka clear status milta hai.',
    },
    {
      step: '04',
      title: 'Next Action & Protection',
      desc: 'Agar fraud hai, toh 1930 cyber helpline, card freeze steps aur emergency recovery guidance turant screen par milti hai.',
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '48px', paddingBottom: '32px' }}>
      {/* Hero Header */}
      <section
        style={{
          background: 'radial-gradient(ellipse at top, rgba(20, 184, 166, 0.15) 0%, rgba(10, 15, 29, 0.95) 70%)',
          border: '1px solid rgba(20, 184, 166, 0.25)',
          borderRadius: '24px',
          padding: '48px 36px',
          textAlign: 'center',
          position: 'relative',
          overflow: 'hidden',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.4)',
        }}
      >
        <div style={{ maxWidth: '860px', margin: '0 auto' }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '6px 16px',
              borderRadius: '999px',
              background: 'rgba(20, 184, 166, 0.15)',
              border: '1px solid rgba(20, 184, 166, 0.3)',
              color: 'var(--teal)',
              fontSize: '13px',
              fontWeight: 700,
              marginBottom: '20px',
              letterSpacing: '0.5px',
            }}
          >
            <Shield size={16} />
            <span>ALL-IN-ONE CYBER DEFENSE PLATFORM</span>
          </div>

          <h1
            style={{
              fontSize: 'clamp(32px, 5vw, 48px)',
              fontWeight: 900,
              color: '#fff',
              lineHeight: 1.2,
              marginBottom: '18px',
              letterSpacing: '-1px',
            }}
          >
            Cyber Frauds & Malware Se Suraksha,{' '}
            <span style={{
              background: 'linear-gradient(135deg, var(--teal), var(--cyan))',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}>
              Ab Har Kisi Ke Liye Aasan
            </span>
          </h1>

          <p
            style={{
              fontSize: '17px',
              color: 'var(--text-muted)',
              lineHeight: 1.6,
              marginBottom: '32px',
              maxWidth: '740px',
              margin: '0 auto 32px auto',
            }}
          >
            OneClick ek aisi security suite hai jahan <b>aam citizen</b> bina kisi technical knowledge ke apne aap ko fraud se bacha sakta hai, aur <b>power users / developers</b> deep APK decompilation, SSL verification aur port scanning kar sakte hain.
          </p>

          {/* Quick CTA Buttons */}
          <div style={{ display: 'flex', justifyContent: 'center', gap: '14px', flexWrap: 'wrap' }}>
            <button
              onClick={() => onNavigate('shield')}
              className="btn btn-primary"
              style={{
                padding: '14px 28px',
                fontSize: '16px',
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                boxShadow: '0 4px 20px rgba(20, 184, 166, 0.4)',
              }}
            >
              <span>🛡️ Check a Suspicious Message / Number</span>
              <ArrowRight size={18} />
            </button>

            <button
              onClick={() => onNavigate('single')}
              className="btn btn-secondary"
              style={{
                padding: '14px 24px',
                fontSize: '16px',
                fontWeight: 600,
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <span>🔍 Scan an APK File</span>
            </button>
          </div>
        </div>
      </section>

      {/* Services & Tools Showcase Grid */}
      <section>
        <div style={{ textAlign: 'center', marginBottom: '36px' }}>
          <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--cyan)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
            KYA SERVICE DE RAHE HAIN?
          </div>
          <h2 style={{ fontSize: '32px', fontWeight: 800, color: '#fff', letterSpacing: '-0.5px' }}>
            OneClick Ki Samast Suraksha Sevaayein
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '15px', maxWidth: '650px', margin: '8px auto 0 auto' }}>
            Niche diye gaye har ek tool ko aasan bhasha me samjhein aur ek click par use karna shuru karein:
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: '22px' }}>
          {tools.map((t) => (
            <div
              key={t.id}
              className="card"
              style={{
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                padding: '28px',
                background: 'var(--bg-card)',
                border: `1px solid ${t.border}`,
                transition: 'all 0.25s ease',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = t.color;
                e.currentTarget.style.transform = 'translateY(-4px)';
                e.currentTarget.style.boxShadow = `0 12px 30px ${t.bg}`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = t.border;
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <div>
                {/* Header Icon + Badge */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                  <div
                    style={{
                      width: '54px',
                      height: '54px',
                      borderRadius: '12px',
                      background: t.bg,
                      border: `1px solid ${t.border}`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    {t.icon}
                  </div>
                  <span
                    style={{
                      padding: '4px 10px',
                      borderRadius: '999px',
                      fontSize: '11px',
                      fontWeight: 700,
                      background: t.bg,
                      color: t.color,
                      border: `1px solid ${t.border}`,
                    }}
                  >
                    {t.badge}
                  </span>
                </div>

                {/* Title & Description */}
                <h3 style={{ fontSize: '19px', fontWeight: 800, color: '#fff', marginBottom: '10px' }}>
                  {t.title}
                </h3>
                <p style={{ color: 'var(--text-muted)', fontSize: '14px', lineHeight: 1.6, marginBottom: '18px' }}>
                  {t.desc}
                </p>

                {/* Kaise Kaam Karta Hai */}
                <div
                  style={{
                    background: 'rgba(0, 0, 0, 0.35)',
                    padding: '12px 14px',
                    borderRadius: '8px',
                    border: '1px solid var(--border)',
                    marginBottom: '14px',
                  }}
                >
                  <div style={{ fontSize: '11.5px', fontWeight: 800, color: 'var(--cyan)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '4px' }}>
                    ⚙️ Kaise Kaam Karta Hai:
                  </div>
                  <div style={{ fontSize: '12.5px', color: '#cbd5e1', lineHeight: 1.5 }}>
                    {t.howItWorks}
                  </div>
                </div>

                {/* Kiske Liye Hai */}
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '20px' }}>
                  👥 <b>Kiske Liye:</b> {t.whoUses}
                </div>
              </div>

              {/* Action Button */}
              <button
                onClick={() => onNavigate(t.id)}
                className="btn btn-secondary"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                  fontWeight: 700,
                  fontSize: '13.5px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  borderColor: t.border,
                  color: '#fff',
                }}
              >
                <span>Tool Kholein</span>
                <ChevronRight size={15} color={t.color} />
              </button>
            </div>
          ))}
        </div>
      </section>

      {/* 4-Step Process Section */}
      <section
        style={{
          background: 'linear-gradient(135deg, rgba(16, 23, 38, 0.9), rgba(15, 23, 42, 0.9))',
          border: '1px solid var(--border)',
          borderRadius: '20px',
          padding: '36px',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--teal)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px' }}>
            SIMPLE WORKFLOW
          </div>
          <h2 style={{ fontSize: '26px', fontWeight: 800, color: '#fff' }}>
            Yeh Kaam Kaise Karta Hai? (4 Simple Steps)
          </h2>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: '20px' }}>
          {steps.map((s, idx) => (
            <div
              key={idx}
              style={{
                background: 'var(--bg-card)',
                padding: '20px',
                borderRadius: '12px',
                border: '1px solid var(--border)',
                position: 'relative',
              }}
            >
              <div
                style={{
                  fontSize: '28px',
                  fontWeight: 900,
                  color: 'rgba(20, 184, 166, 0.3)',
                  marginBottom: '10px',
                  fontFamily: 'monospace',
                }}
              >
                {s.step}
              </div>
              <h4 style={{ fontSize: '16px', fontWeight: 700, color: '#fff', marginBottom: '8px' }}>
                {s.title}
              </h4>
              <p style={{ color: 'var(--text-muted)', fontSize: '13px', lineHeight: 1.5, margin: 0 }}>
                {s.desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Emergency Assistance Footer Banner */}
      <section
        style={{
          background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.12), rgba(220, 38, 38, 0.08))',
          border: '1px solid rgba(239, 68, 68, 0.35)',
          borderRadius: '16px',
          padding: '28px 32px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '20px',
        }}
      >
        <div style={{ maxWidth: '780px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#f87171', fontWeight: 800, fontSize: '14px', marginBottom: '6px' }}>
            <AlertTriangle size={18} />
            <span>KISI FINANCIAL SCAM YA FRAUD KA SHIKAAR HO GAYE HAIN?</span>
          </div>
          <h3 style={{ fontSize: '22px', fontWeight: 800, color: '#fff', marginBottom: '6px' }}>
            Ghabrayein nahi, 2-Hour Golden Window me turant 1930 par call karein.
          </h3>
          <p style={{ color: '#cbd5e1', fontSize: '14px', lineHeight: 1.5, margin: 0 }}>
            Bharat Sarkar ke National Cybercrime Portal (I4C) dwara operated helpline bank se direct connect hokar criminal ke account ko turant freeze karti hai.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <a
            href="tel:1930"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              background: 'var(--red)',
              color: '#fff',
              padding: '12px 22px',
              borderRadius: '10px',
              textDecoration: 'none',
              fontWeight: 800,
              fontSize: '15px',
              boxShadow: '0 4px 15px rgba(239, 68, 68, 0.4)',
            }}
          >
            <PhoneCall size={18} />
            <span>Call 1930</span>
          </a>
          <a
            href="https://cybercrime.gov.in"
            target="_blank"
            rel="noreferrer"
            className="btn btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '14px', padding: '12px 18px' }}
          >
            <span>cybercrime.gov.in</span>
            <ExternalLink size={14} />
          </a>
        </div>
      </section>
    </div>
  );
};
