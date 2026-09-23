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
      badge: 'Citizen Protection • No Tech Jargon',
      title: 'Smart Shield (Universal Scam & Fraud Detector)',
      objective:
        'Aam naagrik, pariwar ke bade-buzurg, aur WhatsApp/UPI users ko modern cyber thagon (Digital Arrest, Bijli Bill cut, Fake Courier, Work-From-Home Task scams) se bachana. Aam insaan ko kisi complicated security tool ki training ki zaroorat nahi honi chahiye — bas ek box me paste karein aur turant sach samne aa jaye.',
      howItWorks:
        'Jaise hi user koi input deta hai, hamara AI Engine pehle pehchanta hai ki yeh Phone number hai, UPI ID hai, Web Link hai ya poora Message. Iske baad yeh Indian cybercrime patterns, reported scammer numbers, fake bank handles, aur malicious domains ki live intelligence se cross-check karta hai. Saath hi message me agar koi confidential OTP ya PIN ho toh use turant mask (chhupa) deta hai taaki user ka data leak na ho.',
      verdictOutcome:
        '🟢 SURAKSHIT (SAFE) / 🟡 SAVDHAAN (CAUTION) / 🔴 KHATRA (DANGER) ka seedha traffic-light verdict, aur agla kadam jaise National Cyber Helpline 1930 par call karne ka direct button.',
      whoUses: 'Har aam citizen jise WhatsApp, SMS ya call par koi anjaan offer ya dhar-pakad ki dhamki aayi ho.',
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
        'Fake banking apps aur spyware APKs (jaise WhatsApp par bheje gaye fake SBI YONO, PM Awas Yojana, Marriage Invitation Card APKs) se phone ko bachana. Phone par install hone se pehle hi pata chal jaye ki yeh app asli hai ya aapka data aur SMS churane wala malware.',
      howItWorks:
        'Yeh system 3 stariye (3-layer) scanning par kaam karta hai: (1) Layer 1: File ka unique cryptographic SHA-256 fingerprint nikal kar 70+ global antivirus engines (VirusTotal) par match karta hai. (2) Layer 2: APK ko bina run kiye safe tareeqe se decompile karta hai aur manifest permissions (SMS read/send, overlay popup, background audio record) aur hidden DexClassLoader payloads dhoondhta hai. (3) Layer 3: AI Machine Learning Classifier code features ke aadhar par 0 se 100% ka exact Risk Score generate karta hai.',
      verdictOutcome:
        'App ka name, package name, dangerous permissions list, obfuscation analysis, aur downloadable forensic PDF report.',
      whoUses: 'Android users, IT professionals, app testers, aur mobile security researchers.',
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
        'Bank login pages, PAN/Aadhaar update portals, aur e-commerce sites ke duplicate clones (typosquatting links) ko be-naqab karna, taaki user fraud link par apna username, password ya credit card details submit na kare.',
      howItWorks:
        'Yeh URL ko kholne ke bajaye ek isolated backend sandbox me inspect karta hai. Levenshtein string-distance algorithm se check hota hai ki domain SBI, HDFC, Paytm ya Amazon ki spelling copy karke banayi gayi hai ya nahi (e.g. `sbi-kyc-update.com`). Saath hi WHOIS protocol se Domain Age check karta hai (zyadatar fraud websites 2 se 10 din purani hoti hain), aur HTML page ke andar chhupe huye password forms aur sneaky meta-refresh redirects ko extract karta hai.',
      verdictOutcome:
        'Website ka Safe/Suspicious/Malicious verdict, Redirection chain, Domain registration age, aur input forms ka audit.',
      whoUses: 'Net banking karne wale, SMS/Email me aaye link par shaq karne wale users.',
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
        'Log anjaane me customer care ya dosto ko SMS ka screenshot ya copied text bhej dete hain jisme unka banking OTP likha hota hai. Is tool ka udyesy hai ki kisi bhi text ya message ko share karne se pehle usme se har secret OTP aur transaction PIN ko auto-censor kar diya jaye.',
      howItWorks:
        'Yeh multi-lingual context keywords (OTP, Verification Code, Pin Hai, Code Hai) ke aas-paas ke 4 se 8 digit ke numeric aur alphanumeric tokens ko regex proximity scanning se scan karta hai. Jaise hi koi code milta hai, yeh use safe placeholder `[REDACTED-OTP]` se replace kar deta hai. Real code values server ke database ya logs me kabhi store nahi hoti.',
      verdictOutcome:
        'Sanitized & copy-ready safe text jise aap bina kisi dar ke kisi bhi forum, support agent ya friend ke saath share kar sakte hain.',
      whoUses: 'Customer support par baat karne wale users aur SMS error share karne wale log.',
      color: '#a855f7',
      bg: 'rgba(168, 85, 247, 0.08)',
      border: 'rgba(168, 85, 247, 0.3)',
    },
    {
      id: 'scam',
      icon: <PhoneCall size={32} color="var(--red)" />,
      badge: 'Community Intel & Pwned Check',
      title: 'Scam DB & Password Breach Checker',
      objective:
        'Fraudsters ke un numbers aur UPI handles ki pehchan karna jo pehle se logo ko loot chuke hain, aur user ko yeh batana ki unka personal password dark web data breaches me leak toh nahi ho chuka.',
      howItWorks:
        'Scam Lookup: Yeh crowdsourced SQLite database me reported phone numbers aur UPI handles ko match karta hai. Password Breach Checker: Yeh Troy Hunt ke HaveIBeenPwned API ke sath k-Anonymity model par kaam karta hai — aapka asli password kabhi network par nahi jata; sirf uske SHA-1 hash ke pehle 5 characters bheje jate hain aur mathematically match kiya jata hai ki password kitni baar leak ho chuka hai.',
      verdictOutcome:
        'Kitni baar report hua, kis category ka scam tha (KYC, Lottery, Job), aur password kitne data breaches me samne aaya.',
      whoUses: 'OLX/Quikr par anjaan payment lene wale, suspicious call paane wale, aur account security audit karne wale users.',
      color: 'var(--red)',
      bg: 'rgba(239, 68, 68, 0.08)',
      border: 'rgba(239, 68, 68, 0.3)',
    },
    {
      id: 'tools',
      icon: <Server size={32} color="#3b82f6" />,
      badge: 'Infra & Web Hardening Suite',
      title: 'Web & Infrastructure Security Tools',
      objective:
        'Websites, servers aur domains ki security vulnerabilities ko scan karna taaki attackers unke users ko hijack na kar sakein (Clickjacking, MIME Sniffing, Email Phishing, Open Port Exposure).',
      howItWorks:
        'Isme 4 mukhya module hain: (1) HTTP Security Headers Check: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), aur X-Frame-Options ko audit karke A se F tak grade deta hai. (2) SSL/TLS Cert Inspector: Socket-level handshakes se certificate issuer, expiry date, aur cipher strength verify karta hai. (3) Email Spoofing Defense: DNS-over-HTTPS (DoH) se domain ke SPF aur DMARC records check karta hai ki koi us domain ke naam par nakli email toh nahi bhej sakta. (4) Port Exposure Scanner: High-risk ports (SSH, RDP, Telnet, MySQL) open hain ya closed, yeh scan karta hai.',
      verdictOutcome:
        'Letter grade score, missing security headers recommendations, expiry countdown, aur port risk categorization.',
      whoUses: 'Web developers, sysadmins, DevOps engineers, aur cybersecurity analysts.',
      color: '#3b82f6',
      bg: 'rgba(59, 130, 246, 0.08)',
      border: 'rgba(59, 130, 246, 0.3)',
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
            <span>ALL-IN-ONE CYBER DEFENSE PLATFORM</span>
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
            Cyber Frauds & Malware Se Suraksha,{' '}
            <span
              style={{
                background: 'linear-gradient(135deg, var(--teal), var(--cyan))',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}
            >
              Ab Har Kisi Ke Liye Aasan
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
            OneClick ka lakshya cyber security ko lab se nikal kar aam naagrik ki mutthi me dena hai. Yahan <b>bina kisi technical knowledge</b> ke koi bhi vyakti WhatsApp scams, fake banking APKs, aur phishing links ko pehchan sakta hai, aur <b>developers</b> deep code & infrastructure audits kar sakte hain.
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
            HAMARI SEVAYEIN AUR UNKE PICHHE KA UDDESHYA
          </div>
          <h2 style={{ fontSize: '34px', fontWeight: 800, color: '#fff', letterSpacing: '-0.5px' }}>
            Har Tool Ki Puraani Pith-Bhoomi Aur Karyapranali
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '15.5px', maxWidth: '720px', margin: '10px auto 0 auto', lineHeight: 1.6 }}>
            Niche samjhein ki har ek tool ko kyu banaya gaya hai, iska mool uddeshya (purpose) kya hai, yeh takneeki roop se kaise kaam karta hai, aur iska result kya hota hai:
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
                        TOOL #{index + 1}
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
                  <span>Abhi Use Karein</span>
                  <ChevronRight size={15} />
                </button>
              </div>

              {/* Three Detailed Paragraph Blocks */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {/* 1. Uddeshya (Objective) */}
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
                    <span>Tool Banane Ka Uddeshya (Objective & Background):</span>
                  </div>
                  <p style={{ color: '#e2e8f0', fontSize: '14.5px', lineHeight: 1.65, margin: 0 }}>
                    {t.objective}
                  </p>
                </div>

                {/* 2. Kaise Kaam Karta Hai (How it Works) */}
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
                    <span>Yeh Kaam Kaise Karta Hai? (Technical Mechanism):</span>
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
                      📊 Kya Outcome / Result Milta Hai:
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
                      👥 Kiske Liye Sabse Labhdayak Hai:
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
            SIMPLE WORKFLOW
          </div>
          <h2 style={{ fontSize: '28px', fontWeight: 800, color: '#fff' }}>
            OneClick Par Kaise Check Karein? (4 Simple Steps)
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
