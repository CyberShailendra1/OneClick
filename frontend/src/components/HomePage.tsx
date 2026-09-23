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
  LifeBuoy,
  Landmark,
  EyeOff,
  UserX,
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

      {/* Official Government Cybercrime & Stolen Phone Portals */}
      <section
        style={{
          background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.9))',
          border: '1px solid rgba(59, 130, 246, 0.3)',
          borderRadius: '20px',
          padding: '38px',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '4px 14px', borderRadius: '999px', background: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa', fontSize: '12px', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
            <Landmark size={14} />
            <span>Official Government Portals & Services</span>
          </div>
          <h2 style={{ fontSize: '30px', fontWeight: 800, color: '#fff', letterSpacing: '-0.5px' }}>
            Government Portals for Cyber Fraud, Stolen Phones & Citizen Safety
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '15px', maxWidth: '780px', margin: '8px auto 0 auto', lineHeight: 1.6 }}>
            The Government of India (Ministry of Home Affairs, DoT, MeitY, and CERT-In) provides official web portals to report crimes, block stolen devices, and track mobile connections. Here is the complete verified directory and how to use each service:
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '22px' }}>
          {/* Service 1: CEIR */}
          <div
            className="card"
            style={{
              padding: '24px',
              background: 'var(--bg-card)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <span style={{ padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 800, background: 'rgba(239, 68, 68, 0.15)', color: '#f87171' }}>
                  LOST / STOLEN PHONE
                </span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Dept of Telecom (DoT)</span>
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>
                CEIR (Central Equipment Identity Register)
              </h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.5, marginBottom: '14px' }}>
                Official portal to remotely block, blacklist, and track lost or stolen mobile phones across all Indian telecom networks using IMEI.
              </p>

              <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--cyan)', marginBottom: '6px' }}>
                  📌 How to Use:
                </div>
                <ol style={{ margin: 0, paddingLeft: '18px', fontSize: '12.5px', color: '#cbd5e1', lineHeight: 1.5 }}>
                  <li>First, lodge a digital Police Missing Complaint / FIR.</li>
                  <li>Get a duplicate SIM card from your telecom operator.</li>
                  <li>Visit CEIR, enter your 15-digit IMEI number, invoice, and FIR copy.</li>
                  <li>Once submitted, the phone is blacklisted nationwide and tracked immediately if a new SIM is inserted.</li>
                </ol>
              </div>
            </div>

            <a
              href="https://www.ceir.gov.in"
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ width: '100%', justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '8px', color: '#60a5fa' }}
            >
              <span>Visit ceir.gov.in</span>
              <ExternalLink size={14} />
            </a>
          </div>

          {/* Service 2: National Cyber Crime Portal */}
          <div
            className="card"
            style={{
              padding: '24px',
              background: 'var(--bg-card)',
              border: '1px solid rgba(20, 184, 166, 0.3)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <span style={{ padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 800, background: 'rgba(20, 184, 166, 0.15)', color: 'var(--teal)' }}>
                  FINANCIAL FRAUD & CYBERCRIME
                </span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>MHA - I4C</span>
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>
                National Cyber Crime Reporting Portal (NCRP)
              </h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.5, marginBottom: '14px' }}>
                Central citizen portal to lodge official online complaints for financial fraud, unauthorized banking transactions, social media extortion, and identity theft.
              </p>

              <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--cyan)', marginBottom: '6px' }}>
                  📌 How to Use:
                </div>
                <ol style={{ margin: 0, paddingLeft: '18px', fontSize: '12.5px', color: '#cbd5e1', lineHeight: 1.5 }}>
                  <li>For financial fraud, call <b>1930</b> immediately or click "Report Financial Fraud".</li>
                  <li>Register using your mobile number and state.</li>
                  <li>Upload transaction screenshots, bank statements, and fraudster numbers/URLs.</li>
                  <li>Receive a formal Acknowledgement Number to track police investigation status.</li>
                </ol>
              </div>
            </div>

            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ width: '100%', justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--teal)' }}
            >
              <span>Visit cybercrime.gov.in</span>
              <ExternalLink size={14} />
            </a>
          </div>

          {/* Service 3: Sanchar Saathi - TAFCOP */}
          <div
            className="card"
            style={{
              padding: '24px',
              background: 'var(--bg-card)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <span style={{ padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 800, background: 'rgba(245, 158, 11, 0.15)', color: 'var(--amber)' }}>
                  UNAUTHORIZED SIM CARDS
                </span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Sanchar Saathi (DoT)</span>
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>
                TAFCOP (Telecom Analytics for Fraud Management)
              </h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.5, marginBottom: '14px' }}>
                Allows citizens to check how many active mobile connections have been issued under their Aadhaar or identity document, and report unknown numbers for disconnection.
              </p>

              <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--cyan)', marginBottom: '6px' }}>
                  📌 How to Use:
                </div>
                <ol style={{ margin: 0, paddingLeft: '18px', fontSize: '12.5px', color: '#cbd5e1', lineHeight: 1.5 }}>
                  <li>Open the TAFCOP portal on Sanchar Saathi.</li>
                  <li>Enter your active mobile number and submit the received OTP.</li>
                  <li>Review the full list of all mobile numbers issued under your identity.</li>
                  <li>Select any unknown number and choose "Not My Number" to request immediate termination.</li>
                </ol>
              </div>
            </div>

            <a
              href="https://tafcop.sancharsaathi.gov.in"
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ width: '100%', justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--amber)' }}
            >
              <span>Visit tafcop.sancharsaathi.gov.in</span>
              <ExternalLink size={14} />
            </a>
          </div>

          {/* Service 4: Chakshu */}
          <div
            className="card"
            style={{
              padding: '24px',
              background: 'var(--bg-card)',
              border: '1px solid rgba(168, 85, 247, 0.3)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <span style={{ padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 800, background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc' }}>
                  SUSPECTED FRAUD REPORTING
                </span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>DoT Facility</span>
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>
                Chakshu (Suspected Fraud Communication)
              </h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.5, marginBottom: '14px' }}>
                Citizen reporting facility for suspected fraudulent communication received through SMS, WhatsApp, or phone calls (e.g. KYC expiry, electricity power cut, digital arrest, lottery).
              </p>

              <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--cyan)', marginBottom: '6px' }}>
                  📌 How to Use:
                </div>
                <ol style={{ margin: 0, paddingLeft: '18px', fontSize: '12.5px', color: '#cbd5e1', lineHeight: 1.5 }}>
                  <li>Visit Sanchar Saathi and select the Chakshu option.</li>
                  <li>Select the category of scam (Bank KYC, Electricity bill, Lottery, Sextortion, Job).</li>
                  <li>Upload a screenshot of the message/call log and the scammer's phone number.</li>
                  <li>Authorities inspect and disconnect rogue numbers across all Indian telecom circles.</li>
                </ol>
              </div>
            </div>

            <a
              href="https://sancharsaathi.gov.in/sfc"
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ width: '100%', justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '8px', color: '#c084fc' }}
            >
              <span>Visit sancharsaathi.gov.in/sfc</span>
              <ExternalLink size={14} />
            </a>
          </div>

          {/* Service 5: CERT-In */}
          <div
            className="card"
            style={{
              padding: '24px',
              background: 'var(--bg-card)',
              border: '1px solid rgba(99, 102, 241, 0.3)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <span style={{ padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 800, background: 'rgba(99, 102, 241, 0.15)', color: '#818cf8' }}>
                  CYBER INCIDENT & VULNERABILITY
                </span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>MeitY</span>
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>
                CERT-In (Indian Computer Emergency Response Team)
              </h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.5, marginBottom: '14px' }}>
                National nodal agency for responding to cybersecurity incidents, malware outbreaks, phishing domain takedowns, and security vulnerability disclosures in India.
              </p>

              <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--cyan)', marginBottom: '6px' }}>
                  📌 How to Use:
                </div>
                <ol style={{ margin: 0, paddingLeft: '18px', fontSize: '12.5px', color: '#cbd5e1', lineHeight: 1.5 }}>
                  <li>To report phishing URLs, ransomware, or malware, email <b>incident@cert-in.org.in</b>.</li>
                  <li>Provide attack logs, headers, and sample malicious files.</li>
                  <li>Check official security advisories for Android vulnerabilities, browser zero-days, and patches.</li>
                </ol>
              </div>
            </div>

            <a
              href="https://www.cert-in.org.in"
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ width: '100%', justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '8px', color: '#818cf8' }}
            >
              <span>Visit cert-in.org.in</span>
              <ExternalLink size={14} />
            </a>
          </div>

          {/* Service 6: Cyber Swachhta Kendra */}
          <div
            className="card"
            style={{
              padding: '24px',
              background: 'var(--bg-card)',
              border: '1px solid rgba(34, 197, 94, 0.3)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <span style={{ padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 800, background: 'rgba(34, 197, 94, 0.15)', color: 'var(--green)' }}>
                  FREE BOT REMOVAL & CLEANING
                </span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>MeitY / CERT-In</span>
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>
                Cyber Swachhta Kendra (Botnet Cleaning Center)
              </h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.5, marginBottom: '14px' }}>
                Provides free government-certified malware and botnet removal security tools to clean infected mobile devices, laptops, and desktop computers.
              </p>

              <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 800, color: 'var(--cyan)', marginBottom: '6px' }}>
                  📌 How to Use:
                </div>
                <ol style={{ margin: 0, paddingLeft: '18px', fontSize: '12.5px', color: '#cbd5e1', lineHeight: 1.5 }}>
                  <li>Visit the Cyber Swachhta Kendra security tools portal.</li>
                  <li>Download free verified bot-removal tools for Windows and Android (e.g. M-Kavach 2).</li>
                  <li>Scan your device to detect and remove covert remote-access spyware and trojans.</li>
                </ol>
              </div>
            </div>

            <a
              href="https://www.csk.gov.in"
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ width: '100%', justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--green)' }}
            >
              <span>Visit csk.gov.in</span>
              <ExternalLink size={14} />
            </a>
          </div>
        </div>
      </section>

      {/* Non-Consensual Intimate Image (NCII) & Nude Content Takedown Services */}
      <section
        style={{
          background: 'linear-gradient(135deg, rgba(30, 27, 75, 0.95), rgba(49, 46, 129, 0.9))',
          border: '1px solid rgba(168, 85, 247, 0.35)',
          borderRadius: '20px',
          padding: '38px',
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '4px 14px', borderRadius: '999px', background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc', fontSize: '12px', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
            <EyeOff size={14} />
            <span>Digital Privacy & Dignity Protection</span>
          </div>
          <h2 style={{ fontSize: '30px', fontWeight: 800, color: '#fff', letterSpacing: '-0.5px' }}>
            How to Remove Leaked Intimate / Nude Photos & Videos from the Internet
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '15px', maxWidth: '780px', margin: '8px auto 0 auto', lineHeight: 1.6 }}>
            If intimate media, morphed photographs, or sextortion material has been published or threatened to be shared online without consent, victims can legally take down and stop the viral circulation of this content across major tech platforms without having to share the actual media with anyone:
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '22px' }}>
          {/* Service 1: StopNCII.org */}
          <div
            className="card"
            style={{
              padding: '24px',
              background: 'var(--bg-card)',
              border: '1px solid rgba(168, 85, 247, 0.35)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <span style={{ padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 800, background: 'rgba(168, 85, 247, 0.15)', color: '#c084fc' }}>
                  GLOBAL HASH-BLOCKING TECH
                </span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>SWGfL / Meta / Tech Coalition</span>
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>
                StopNCII.org (Stop Non-Consensual Intimate Images)
              </h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.5, marginBottom: '14px' }}>
                Free, privacy-preserving global platform that generates secure digital hashes directly inside your browser to preemptively block and take down leaked intimate photos and videos across Facebook, Instagram, TikTok, OnlyFans, and Threads.
              </p>

              <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 800, color: '#c084fc', marginBottom: '8px' }}>
                  📌 Step-by-Step Usage Guide:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px', color: '#cbd5e1', lineHeight: 1.5 }}>
                  <div>
                    <b>1. Open StopNCII.org in Your Browser:</b> The entire process is 100% private. <u>Your photo or video NEVER leaves your device and is NEVER uploaded to any server</u>.
                  </div>
                  <div>
                    <b>2. Select the File on Your Device:</b> StopNCII runs an algorithm locally in your device's browser to generate a unique digital fingerprint (cryptographic hash value) of that specific photo/video.
                  </div>
                  <div>
                    <b>3. Cryptographic Hash Sharing:</b> Only the numerical hash code is shared with partner tech platforms (Meta, Instagram, TikTok, Reddit).
                  </div>
                  <div>
                    <b>4. Automated Nationwide/Worldwide Block:</b> When an extortionist or fraudster attempts to upload that image or video, the platform's filters recognize the matched hash and immediately block the upload before anyone can view it.
                  </div>
                  <div>
                    <b>5. Keep Your Case PIN:</b> Save the provided 9-digit PIN to check your case status and hash enforcement at any time.
                  </div>
                </div>
              </div>
            </div>

            <a
              href="https://stopncii.org"
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ width: '100%', justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '8px', color: '#c084fc' }}
            >
              <span>Visit stopncii.org</span>
              <ExternalLink size={14} />
            </a>
          </div>

          {/* Service 2: Take It Down */}
          <div
            className="card"
            style={{
              padding: '24px',
              background: 'var(--bg-card)',
              border: '1px solid rgba(236, 72, 153, 0.35)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <span style={{ padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 800, background: 'rgba(236, 72, 153, 0.15)', color: '#f472b6' }}>
                  UNDER 18 & MINOR PROTECTION
                </span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>NCMEC</span>
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>
                Take It Down (For Minors & Young Adults)
              </h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.5, marginBottom: '14px' }}>
                Specialized confidential removal service operated by the National Center for Missing & Exploited Children (NCMEC) for anyone who had nude, partially nude, or sexually explicit photos taken before they turned 18.
              </p>

              <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 800, color: '#f472b6', marginBottom: '8px' }}>
                  📌 Step-by-Step Usage Guide:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px', color: '#cbd5e1', lineHeight: 1.5 }}>
                  <div>
                    <b>1. Anonymous Access:</b> No identity card or parental disclosure is required to start a case.
                  </div>
                  <div>
                    <b>2. On-Device Numerical Hashing:</b> Select the explicit media stored on your phone or PC. A secure hash is computed right on your device.
                  </div>
                  <div>
                    <b>3. Platform Integration:</b> The hash is fed into global social media networks and pornographic hosting aggregators to locate and purge existing copies.
                  </div>
                  <div>
                    <b>4. Legal Action Trigger:</b> Distribution of underage intimate imagery constitutes a severe federal offense (POCSO in India); NCMEC coordinates international law enforcement takedowns.
                  </div>
                </div>
              </div>
            </div>

            <a
              href="https://takeitdown.ncmec.org"
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ width: '100%', justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '8px', color: '#f472b6' }}
            >
              <span>Visit takeitdown.ncmec.org</span>
              <ExternalLink size={14} />
            </a>
          </div>

          {/* Service 3: National Cybercrime Portal - Women & Child Section */}
          <div
            className="card"
            style={{
              padding: '24px',
              background: 'var(--bg-card)',
              border: '1px solid rgba(239, 68, 68, 0.35)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <span style={{ padding: '3px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 800, background: 'rgba(239, 68, 68, 0.15)', color: '#f87171' }}>
                  LEGAL TAKEDOWN & ANONYMOUS REPORT
                </span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Govt of India (MHA)</span>
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', marginBottom: '8px' }}>
                Cybercrime.gov.in: Women & Child Crime Reporting
              </h3>
              <p style={{ color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.5, marginBottom: '14px' }}>
                Official Indian government portal under Section 67 & 67A of the IT Act allowing citizens to file confidential complaints against non-consensual image sharing, deepfake morphing, and cyber sextortion.
              </p>

              <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)', marginBottom: '16px' }}>
                <div style={{ fontSize: '12px', fontWeight: 800, color: '#f87171', marginBottom: '8px' }}>
                  📌 Step-by-Step Usage Guide:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px', color: '#cbd5e1', lineHeight: 1.5 }}>
                  <div>
                    <b>1. Choose "Report Anonymously":</b> You have the legal right to submit complaints anonymously without disclosing your identity publicly on the portal.
                  </div>
                  <div>
                    <b>2. Provide URLs & Social Media Handles:</b> Paste the exact website links, WhatsApp sender numbers, Telegram channels, or Instagram profile handles where the extortion or image hosting occurs.
                  </div>
                  <div>
                    <b>3. Law Enforcement IT Act Notice:</b> Under Indian IT Rules 2021 (Rule 3(2)(b)), social media intermediaries (Instagram, X/Twitter, Google) are legally mandated to remove sexually explicit content within <b>24 hours</b> of receiving notification.
                  </div>
                  <div>
                    <b>4. Intermediary Takedown:</b> Police nodal cyber cells issue official preservation and takedown orders to internet service providers to permanently de-index the content.
                  </div>
                </div>
              </div>
            </div>

            <a
              href="https://cybercrime.gov.in/Webform/Crime_AuthoLogin.aspx"
              target="_blank"
              rel="noreferrer"
              className="btn btn-secondary"
              style={{ width: '100%', justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '8px', color: '#f87171' }}
            >
              <span>File Complaint on cybercrime.gov.in</span>
              <ExternalLink size={14} />
            </a>
          </div>
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
