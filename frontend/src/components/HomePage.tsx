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
  Target,
  Cpu,
  Layers,
  Sparkles,
  LifeBuoy
} from 'lucide-react';

interface HomePageProps {
  onNavigate: (tabId: string) => void;
}

export const HomePage: React.FC<HomePageProps> = ({ onNavigate }) => {
  const tools = [
    {
      id: 'shield',
      icon: <Shield size={32} color="var(--teal)" />,
      badge: 'Citizen Defense • Zero Technical Barrier',
      title: 'Smart Shield (Universal AI Scam Detector)',
      objective:
        'To protect everyday citizens, families, and digital payment users against contemporary social engineering attacks (such as "Digital Arrest" impersonation, electric utility disconnection threats, fake courier customs holds, and deceptive task jobs). The system eliminates security jargon and provides a single, intuitive input where any query is evaluated instantly.',
      howItWorks:
        'When input is provided, the engine automatically identifies whether it is an Indian phone number, a UPI ID, a web URL, or an unstructured message. It cross-examines the input against cyber threat patterns, reported fraud repositories, known deceptive handles, and real-time phishing heuristics. In parallel, it automatically detects and redacts sensitive OTPs and authentication tokens to prevent accidental data leaks.',
      verdictOutcome:
        '🟢 SAFE / 🟡 CAUTION / 🔴 DANGER traffic-light verdict, accompanied by actionable recommendations and immediate access to the National Cybercrime Helpline (1930).',
      whoUses: 'General public, smartphone users, and recipients of unverified WhatsApp or SMS payment solicitations.',
      color: 'var(--teal)',
      bg: 'rgba(20, 184, 166, 0.08)',
      border: 'rgba(20, 184, 166, 0.3)',
    },
    {
      id: 'single',
      icon: <Smartphone size={32} color="var(--cyan)" />,
      badge: '3-Layer Deep Static Engine',
      title: 'Android APK Malware & Spyware Scanner',
      objective:
        'To identify trojanized and malicious Android application packages (such as cloned banking apps, fake government relief schemes, and spyware masquerading as digital invitations) prior to device installation, stopping data exfiltration and SMS interception at the threshold.',
      howItWorks:
        'Employs a comprehensive three-tier inspection pipeline: (1) Layer 1 computes the cryptographic SHA-256 hash and queries global threat intelligence databases (VirusTotal). (2) Layer 2 performs deep static decompilation without code execution, auditing manifest permissions (such as background SMS interception, SYSTEM_ALERT_WINDOW overlays, and Accessibility Service abuse) and searching for dynamic code loaders (DexClassLoader). (3) Layer 3 leverages an AI/heuristic risk-scoring model that generates an overall threat probability score from 0% to 100%.',
      verdictOutcome:
        'Detailed package metadata, forensic manifest permission breakdown, obfuscation metrics, and an exportable forensic report.',
      whoUses: 'Android device users, IT security administrators, app developers, and mobile forensics auditors.',
      color: 'var(--cyan)',
      bg: 'rgba(6, 182, 212, 0.08)',
      border: 'rgba(6, 182, 212, 0.3)',
    },
    {
      id: 'phishing',
      icon: <Globe size={32} color="var(--amber)" />,
      badge: 'URL & Clone Phishing Defense',
      title: 'Phishing & Fake Website Deep Inspector',
      objective:
        'To expose deceptive lookalike websites and typosquatted domains imitating major banking portals, identity verification portals, and retail services before users disclose credentials or financial card details.',
      howItWorks:
        'Analyzes the submitted target within an isolated server environment without exposing the client browser. It calculates the Levenshtein string distance against legitimate institutional brands, checks WHOIS domain registration age (as disposable phishing campaigns typically rely on newly registered domains), and inspects raw page DOM structures for obfuscated credential forms and deceptive meta-refresh redirections.',
      verdictOutcome:
        'Safe, Suspicious, or Malicious classification, full HTTP redirect chain visualization, domain registration age metrics, and form input security audits.',
      whoUses: 'Online banking clients, digital shoppers, and recipients of unsolicited account update messages.',
      color: 'var(--amber)',
      bg: 'rgba(245, 158, 11, 0.08)',
      border: 'rgba(245, 158, 11, 0.3)',
    },
    {
      id: 'otp',
      icon: <Lock size={32} color="#a855f7" />,
      badge: 'Privacy & Token Masking',
      title: 'OTP Guard (Auto-Redaction & Privacy Shield)',
      objective:
        'To prevent accidental disclosure of one-time passwords, temporary access pins, and transaction authorization codes when sharing screenshots, messages, or support tickets with third parties.',
      howItWorks:
        'Applies high-speed regular expression patterns anchored by contextual verification keywords. Numeric and alphanumeric tokens located within proximity of authentication phrases are automatically identified and replaced with secure `[REDACTED-OTP]` tokens. Raw verification values are never retained in server logs or databases.',
      verdictOutcome:
        'Clean, sanitized, and safely shareable text where all authentication codes are masked.',
      whoUses: 'Users communicating with customer support channels, technical forums, or transmitting error logs.',
      color: '#a855f7',
      bg: 'rgba(168, 85, 247, 0.08)',
      border: 'rgba(168, 85, 247, 0.3)',
    },
    {
      id: 'scam',
      icon: <PhoneCall size={32} color="var(--red)" />,
      badge: 'Threat Intelligence & Credential Audit',
      title: 'Scam Intelligence & Password Breach Checker',
      objective:
        'To provide immediate intelligence on suspect contact numbers and virtual payment addresses, while empowering users to verify whether their credentials have been compromised in historical public data breaches.',
      howItWorks:
        'Performs indexed queries against structured threat databases for reported phone numbers and UPI payment addresses. For credential breach verification, it implements the industry-standard k-Anonymity model: only the first five characters of the SHA-1 password hash are queried against breached credential stores, guaranteeing zero client password transmission across the wire.',
      verdictOutcome:
        'Report history, category categorization, and exact breach count frequencies to prompt timely password rotation.',
      whoUses: 'Peer-to-peer marketplace users, online transactors, and individuals managing credential hygiene.',
      color: 'var(--red)',
      bg: 'rgba(239, 68, 68, 0.08)',
      border: 'rgba(239, 68, 68, 0.3)',
    },
    {
      id: 'tools',
      icon: <Server size={32} color="#3b82f6" />,
      badge: 'Infrastructure Hardening Suite',
      title: 'Web & Infrastructure Security Tools',
      objective:
        'To inspect and evaluate public-facing domains, web properties, and service endpoints for critical misconfigurations that expose systems and users to transport-layer eavesdropping, email spoofing, and service compromise.',
      howItWorks:
        'Operates four distinct diagnostic modules: (1) HTTP Security Headers Analyzer: Evaluates HSTS, CSP, and framing protection, calculating an authoritative compliance letter grade (A to F). (2) SSL/TLS Certificate Inspector: Connects via low-level TLS handshakes to verify cryptographic validity, issuer chains, and cipher suites. (3) Email Spoofing Defense: Uses DNS-over-HTTPS (DoH) queries to audit SPF and DMARC enforcement policies. (4) Port Exposure Scanner: Determines the operational state of critical service ports (SSH, RDP, Telnet, Database).',
      verdictOutcome:
        'Comprehensive security grade, remediation recommendations, certificate expiration countdowns, and network exposure reports.',
      whoUses: 'Web developers, system engineers, DevOps personnel, and cybersecurity evaluators.',
      color: '#3b82f6',
      bg: 'rgba(59, 130, 246, 0.08)',
      border: 'rgba(59, 130, 246, 0.3)',
    },
  ];

  const steps = [
    {
      step: '01',
      title: 'Submit Target Input',
      desc: 'Paste or upload any suspicious phone number, UPI address, website link, SMS/chat message, or APK file into the analyzer.',
    },
    {
      step: '02',
      title: 'Multi-Engine Processing',
      desc: 'The backend coordinates static decompilation, heuristic threat detection, cryptographic hash queries, and database lookups.',
    },
    {
      step: '03',
      title: 'Clear Safety Verdict',
      desc: 'Receive an immediate traffic-light determination (🟢 Safe, 🟡 Caution, 🔴 Danger) free from convoluted technical terminology.',
    },
    {
      step: '04',
      title: 'Actionable Remediation',
      desc: 'Access verified emergency checklists, recovery guidance, and direct hotlines to freeze unauthorized accounts and report fraud.',
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '52px', paddingBottom: '32px' }}>
      {/* Hero Header */}
      <section
        style={{
          background: 'radial-gradient(ellipse at top, rgba(20, 184, 166, 0.18) 0%, rgba(10, 15, 29, 0.98) 70%)',
          border: '1px solid rgba(20, 184, 166, 0.3)',
          borderRadius: '24px',
          padding: '52px 36px',
          textAlign: 'center',
          position: 'relative',
          overflow: 'hidden',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.5)',
        }}
      >
        <div style={{ maxWidth: '900px', margin: '0 auto' }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '6px 18px',
              borderRadius: '999px',
              background: 'rgba(20, 184, 166, 0.15)',
              border: '1px solid rgba(20, 184, 166, 0.35)',
              color: 'var(--teal)',
              fontSize: '13px',
              fontWeight: 800,
              marginBottom: '22px',
              letterSpacing: '1px',
            }}
          >
            <Shield size={16} />
            <span>COMPREHENSIVE CYBER DEFENSE PLATFORM</span>
          </div>

          <h1
            style={{
              fontSize: 'clamp(32px, 5.5vw, 50px)',
              fontWeight: 900,
              color: '#fff',
              lineHeight: 1.15,
              marginBottom: '20px',
              letterSpacing: '-1px',
            }}
          >
            Protection from Cyber Fraud & Malware,{' '}
            <span
              style={{
                background: 'linear-gradient(135deg, var(--teal), var(--cyan))',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}
            >
              Accessible to Everyone
            </span>
          </h1>

          <p
            style={{
              fontSize: '17px',
              color: '#cbd5e1',
              lineHeight: 1.7,
              marginBottom: '32px',
              maxWidth: '780px',
              margin: '0 auto 32px auto',
            }}
          >
            OneClick delivers enterprise-grade security diagnostics through an intuitive interface. Everyday citizens can effortlessly detect social engineering scams and fake banking files without technical training, while developers and security professionals can conduct deep code and infrastructure audits.
          </p>

          {/* Quick CTA Buttons */}
          <div style={{ display: 'flex', justifyContent: 'center', gap: '14px', flexWrap: 'wrap' }}>
            <button
              onClick={() => onNavigate('shield')}
              className="btn btn-primary"
              style={{
                padding: '14px 30px',
                fontSize: '16px',
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                boxShadow: '0 4px 25px rgba(20, 184, 166, 0.45)',
              }}
            >
              <span>🛡️ Check a Suspicious Message / Number</span>
              <ArrowRight size={18} />
            </button>

            <button
              onClick={() => onNavigate('single')}
              className="btn btn-secondary"
              style={{
                padding: '14px 26px',
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

      {/* Detailed Services & Objective Section (Paragraph-wise) */}
      <section>
        <div style={{ textAlign: 'center', marginBottom: '44px' }}>
          <div style={{ fontSize: '13px', fontWeight: 800, color: 'var(--cyan)', textTransform: 'uppercase', letterSpacing: '1.2px', marginBottom: '8px' }}>
            OUR SERVICES & SYSTEM ARCHITECTURE
          </div>
          <h2 style={{ fontSize: '34px', fontWeight: 800, color: '#fff', letterSpacing: '-0.5px' }}>
            Detailed Analysis of Every Security Tool
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '15.5px', maxWidth: '740px', margin: '10px auto 0 auto', lineHeight: 1.6 }}>
            Review the rationale behind each specialized diagnostic tool, its technical execution pipeline, and how it delivers actionable security determinations:
          </p>
        </div>

        {/* Stack of Full-Width Deep Paragraph Cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
          {tools.map((t, index) => (
            <div
              key={t.id}
              className="card"
              style={{
                padding: '32px',
                background: 'var(--bg-card)',
                border: `1px solid ${t.border}`,
                borderRadius: '16px',
                position: 'relative',
                boxShadow: '0 8px 30px rgba(0, 0, 0, 0.25)',
              }}
            >
              {/* Card Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '22px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                  <div
                    style={{
                      width: '60px',
                      height: '60px',
                      borderRadius: '14px',
                      background: t.bg,
                      border: `1px solid ${t.border}`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                    }}
                  >
                    {t.icon}
                  </div>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px', flexWrap: 'wrap' }}>
                      <span
                        style={{
                          padding: '3px 12px',
                          borderRadius: '999px',
                          fontSize: '11px',
                          fontWeight: 800,
                          background: t.bg,
                          color: t.color,
                          border: `1px solid ${t.border}`,
                          textTransform: 'uppercase',
                          letterSpacing: '0.8px',
                        }}
                      >
                        {t.badge}
                      </span>
                      <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>
                        MODULE #{index + 1}
                      </span>
                    </div>
                    <h3 style={{ fontSize: '22px', fontWeight: 800, color: '#fff' }}>
                      {t.title}
                    </h3>
                  </div>
                </div>

                <button
                  onClick={() => onNavigate(t.id)}
                  className="btn btn-primary"
                  style={{
                    padding: '9px 18px',
                    fontSize: '13.5px',
                    fontWeight: 700,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    background: t.bg,
                    border: `1px solid ${t.border}`,
                    color: t.color,
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = t.color;
                    e.currentTarget.style.color = '#fff';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = t.bg;
                    e.currentTarget.style.color = t.color;
                  }}
                >
                  <span>Launch Tool</span>
                  <ChevronRight size={15} />
                </button>
              </div>

              {/* Three Detailed Paragraph Blocks */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {/* 1. Objective */}
                <div
                  style={{
                    background: 'rgba(0, 0, 0, 0.25)',
                    padding: '16px 20px',
                    borderRadius: '10px',
                    border: '1px solid rgba(255, 255, 255, 0.05)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: t.color, fontWeight: 800, fontSize: '14px', marginBottom: '6px' }}>
                    <Target size={16} />
                    <span>Purpose & Problem Addressed:</span>
                  </div>
                  <p style={{ color: '#e2e8f0', fontSize: '14.5px', lineHeight: 1.65, margin: 0 }}>
                    {t.objective}
                  </p>
                </div>

                {/* 2. Technical Mechanism */}
                <div
                  style={{
                    background: 'rgba(0, 0, 0, 0.25)',
                    padding: '16px 20px',
                    borderRadius: '10px',
                    border: '1px solid rgba(255, 255, 255, 0.05)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--cyan)', fontWeight: 800, fontSize: '14px', marginBottom: '6px' }}>
                    <Cpu size={16} />
                    <span>Technical Architecture & Mechanism:</span>
                  </div>
                  <p style={{ color: '#cbd5e1', fontSize: '14.5px', lineHeight: 1.65, margin: 0 }}>
                    {t.howItWorks}
                  </p>
                </div>

                {/* 3. Output & Target Audience */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                    gap: '14px',
                  }}
                >
                  <div
                    style={{
                      background: 'rgba(20, 184, 166, 0.05)',
                      padding: '14px 18px',
                      borderRadius: '8px',
                      border: '1px solid rgba(20, 184, 166, 0.2)',
                    }}
                  >
                    <div style={{ fontSize: '12.5px', fontWeight: 800, color: 'var(--teal)', marginBottom: '4px' }}>
                      📊 Diagnostic Output:
                    </div>
                    <div style={{ fontSize: '13.5px', color: '#e2e8f0', lineHeight: 1.5 }}>
                      {t.verdictOutcome}
                    </div>
                  </div>

                  <div
                    style={{
                      background: 'rgba(255, 255, 255, 0.03)',
                      padding: '14px 18px',
                      borderRadius: '8px',
                      border: '1px solid var(--border)',
                    }}
                  >
                    <div style={{ fontSize: '12.5px', fontWeight: 800, color: '#94a3b8', marginBottom: '4px' }}>
                      👥 Primary Beneficiaries:
                    </div>
                    <div style={{ fontSize: '13.5px', color: '#e2e8f0', lineHeight: 1.5 }}>
                      {t.whoUses}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 4-Step Process Section */}
      <section
        style={{
          background: 'linear-gradient(135deg, rgba(16, 23, 38, 0.95), rgba(15, 23, 42, 0.95))',
          border: '1px solid var(--border)',
          borderRadius: '20px',
          padding: '38px',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--teal)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px' }}>
            OPERATIONAL WORKFLOW
          </div>
          <h2 style={{ fontSize: '28px', fontWeight: 800, color: '#fff' }}>
            How OneClick Executes Diagnostics (4-Step Pipeline)
          </h2>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: '20px' }}>
          {steps.map((s, idx) => (
            <div
              key={idx}
              style={{
                background: 'var(--bg-card)',
                padding: '22px',
                borderRadius: '12px',
                border: '1px solid var(--border)',
                position: 'relative',
              }}
            >
              <div
                style={{
                  fontSize: '32px',
                  fontWeight: 900,
                  color: 'rgba(20, 184, 166, 0.35)',
                  marginBottom: '10px',
                  fontFamily: 'monospace',
                }}
              >
                {s.step}
              </div>
              <h4 style={{ fontSize: '16.5px', fontWeight: 700, color: '#fff', marginBottom: '8px' }}>
                {s.title}
              </h4>
              <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.6, margin: 0 }}>
                {s.desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Emergency Assistance Footer Banner */}
      <section
        style={{
          background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(220, 38, 38, 0.08))',
          border: '1px solid rgba(239, 68, 68, 0.4)',
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
            <span>VICTIM OF AN ACTIVE FINANCIAL CYBER INCIDENT?</span>
          </div>
          <h3 style={{ fontSize: '22px', fontWeight: 800, color: '#fff', marginBottom: '6px' }}>
            Immediate action is vital: Contact National Cybercrime Helpline 1930 within the 2-Hour Golden Window.
          </h3>
          <p style={{ color: '#cbd5e1', fontSize: '14px', lineHeight: 1.5, margin: 0 }}>
            Managed by the Ministry of Home Affairs (I4C), the Citizen Financial Cyber Fraud Management System directly communicates with commercial banking networks to freeze fraudulent transactions in real time.
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
