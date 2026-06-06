import React, { useState, useEffect } from 'react'

const VIEW_CONFIG = {
  recruiter:  { label: 'Recruiter View',    icon: '👔', theme: 'recruiter'  },
  advertiser: { label: 'Advertiser View',   icon: '📢', theme: 'advertiser' },
  threat:     { label: 'Threat Actor View', icon: '🎣', theme: 'threat'     },
}

// Ease-out cubic count-up
function useCountUp(target, active) {
  const [val, setVal] = useState(0)
  useEffect(() => {
    if (!active) return
    const dur = 1500
    const start = Date.now()
    function frame() {
      const t = Math.min((Date.now() - start) / dur, 1)
      const eased = 1 - Math.pow(1 - t, 3)
      setVal(Math.round(eased * target))
      if (t < 1) requestAnimationFrame(frame)
    }
    requestAnimationFrame(frame)
  }, [target, active])
  return val
}

function ScoreRing({ score }) {
  const [animated, setAnimated] = useState(false)
  const display = useCountUp(score, animated)

  useEffect(() => {
    const t = setTimeout(() => setAnimated(true), 140)
    return () => clearTimeout(t)
  }, [])

  const cx = 70, cy = 70
  const r  = 50
  const circ = 2 * Math.PI * r

  // Arc fill
  const filled = animated ? (score / 100) * circ : 0

  // Endpoint dot — travels along the arc tip
  const endAngle  = -Math.PI / 2 + (animated ? (score / 100) : 0) * 2 * Math.PI
  const dotX = cx + r * Math.cos(endAngle)
  const dotY = cy + r * Math.sin(endAngle)

  return (
    <svg width="158" height="158" viewBox="0 0 140 140" style={{ display: 'block', overflow: 'visible' }}>
      <defs>
        <linearGradient id="sg" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#818cf8" />
          <stop offset="100%" stopColor="#22d3ee" />
        </linearGradient>

        {/* Bloom filter for the arc glow */}
        <filter id="bloom" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>

        {/* Dot glow */}
        <filter id="dotglow" x="-100%" y="-100%" width="300%" height="300%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="3.5" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Outer orbit guide — dashed ring slightly beyond score ring */}
      <circle
        cx={cx} cy={cy} r="62"
        fill="none"
        stroke="rgba(99, 102, 241, 0.1)"
        strokeWidth="0.75"
        strokeDasharray="3 6"
      />

      {/* Track ring */}
      <circle cx={cx} cy={cy} r={r} fill="none"
        stroke="rgba(255,255,255,0.05)" strokeWidth="8" />

      {/* Bloom halo (soft glow copy of the arc) */}
      <circle
        cx={cx} cy={cy} r={r}
        fill="none"
        stroke="url(#sg)"
        strokeWidth="14"
        strokeLinecap="round"
        strokeDasharray={`${filled} ${circ}`}
        opacity="0.22"
        style={{
          transform: 'rotate(-90deg)',
          transformOrigin: `${cx}px ${cy}px`,
          transition: 'stroke-dasharray 1.5s cubic-bezier(0.4, 0, 0.2, 1)',
        }}
      />

      {/* Score arc */}
      <circle
        cx={cx} cy={cy} r={r}
        fill="none"
        stroke="url(#sg)"
        strokeWidth="8"
        strokeLinecap="round"
        strokeDasharray={`${filled} ${circ}`}
        style={{
          transform: 'rotate(-90deg)',
          transformOrigin: `${cx}px ${cy}px`,
          transition: 'stroke-dasharray 1.5s cubic-bezier(0.4, 0, 0.2, 1)',
        }}
      />

      {/* Glowing satellite dot at arc tip */}
      <g
        filter="url(#dotglow)"
        style={{
          transform: `translate(${dotX}px, ${dotY}px)`,
          transition: 'transform 1.5s cubic-bezier(0.4, 0, 0.2, 1)',
        }}
      >
        <circle r="4.5" fill="#22d3ee" />
        <circle r="8"   fill="#22d3ee" opacity="0.18" />
      </g>

      {/* Score number */}
      <text
        x={cx} y={cy - 6}
        textAnchor="middle"
        fill="#f1f5f9"
        fontSize="28"
        fontWeight="700"
        fontFamily="Inter, sans-serif"
        style={{ fontVariantNumeric: 'tabular-nums' }}
      >
        {display}
      </text>
      <text
        x={cx} y={cy + 12}
        textAnchor="middle"
        fill="#475569"
        fontSize="11"
        fontFamily="Inter, sans-serif"
        letterSpacing="0.04em"
      >
        / 100
      </text>
    </svg>
  )
}

function scoreInfo(score) {
  if (score >= 80) return { title: 'Highly Visible',     desc: 'Active presence on multiple platforms with significant personal data publicly indexed.' }
  if (score >= 60) return { title: 'Moderately Visible', desc: 'Found on several platforms. A few findings worth reviewing.' }
  if (score >= 40) return { title: 'Low Visibility',     desc: 'Limited public footprint. A small number of exposure points detected.' }
  return                  { title: 'Minimal Visibility', desc: 'Little to no public presence found across checked platforms.' }
}

function buildAttackMappings(report) {
  const techniques = []

  const sigMap = {}
  for (const s of (report.public_signals || [])) sigMap[s.id] = s

  const riskIds = new Set((report.exposure_risks || []).map(r => r.id))
  const domain = report.scan_meta?.domain_checked

  const platformIds = ['github', 'gitlab', 'devto', 'hackernews', 'keybase', 'mastodon', 'gravatar']
  const foundCount = platformIds.filter(id => sigMap[id]?.detected).length

  // T1589.002 — Email Addresses
  if (riskIds.has('github_email') || sigMap.gravatar?.detected) {
    const sources = [riskIds.has('github_email') && 'GitHub', sigMap.gravatar?.detected && 'Gravatar'].filter(Boolean)
    techniques.push({
      id: 'T1589.002',
      name: 'Email Addresses',
      tactic: 'Reconnaissance',
      parent: 'T1589 · Gather Victim Identity Information',
      severity: riskIds.has('github_email') ? 'high' : 'medium',
      description: `Email is publicly indexed via ${sources.join(' and ')}, making it a ready-made target for phishing, credential stuffing, and paste-site harvesting — no prior interaction required.`,
    })
  }

  // T1593.003 — Code Repositories
  if (sigMap.github?.detected || sigMap.gitlab?.detected) {
    const repos = [sigMap.github?.detected && 'GitHub', sigMap.gitlab?.detected && 'GitLab'].filter(Boolean)
    techniques.push({
      id: 'T1593.003',
      name: 'Code Repositories',
      tactic: 'Reconnaissance',
      parent: 'T1593 · Search Open Websites/Domains',
      severity: 'medium',
      description: `Public repositories on ${repos.join(' and ')} may expose API keys in commit history, employer context, internal tool names, and technology stack — all useful for crafting targeted attacks.`,
    })
  }

  // T1593.001 — Social Media
  const socialFound = ['mastodon', 'devto', 'hackernews'].filter(id => sigMap[id]?.detected)
  if (socialFound.length > 0) {
    const nameMap = { mastodon: 'Mastodon', devto: 'DEV.to', hackernews: 'HackerNews' }
    techniques.push({
      id: 'T1593.001',
      name: 'Social Media',
      tactic: 'Reconnaissance',
      parent: 'T1593 · Search Open Websites/Domains',
      severity: 'low',
      description: `Profiles on ${socialFound.map(p => nameMap[p]).join(', ')} expose interests, writing style, and daily activity patterns — ideal material for crafting convincing spear-phishing lures.`,
    })
  }

  // T1589 — Cross-platform identity correlation
  if (riskIds.has('cross_platform') || foundCount >= 3) {
    techniques.push({
      id: 'T1589',
      name: 'Gather Victim Identity Information',
      tactic: 'Reconnaissance',
      parent: null,
      severity: foundCount >= 5 ? 'high' : 'medium',
      description: `Consistent identity across ${foundCount} platforms allows automated cross-referencing. A threat actor can build a complete target dossier — name, email, employer, interests, active hours — in minutes with no special tools.`,
    })
  }

  // T1590.002 — DNS (missing SPF / DMARC enables domain spoofing)
  if (riskIds.has('no_spf') || riskIds.has('no_dmarc')) {
    const missing = [riskIds.has('no_spf') && 'SPF', riskIds.has('no_dmarc') && 'DMARC'].filter(Boolean)
    techniques.push({
      id: 'T1590.002',
      name: 'DNS',
      tactic: 'Reconnaissance',
      parent: 'T1590 · Gather Victim Network Information',
      severity: riskIds.has('no_spf') ? 'medium' : 'low',
      description: `Missing ${missing.join(' and ')} records${domain ? ` on ${domain}` : ''} enables domain spoofing. An attacker can send email appearing to originate from your domain — receiving servers have no policy to reject it.`,
    })
  }

  // T1590.001 — Domain Properties (WHOIS / domain age)
  if (domain && (riskIds.has('new_domain') || riskIds.has('young_domain') || sigMap.domain_age?.detected)) {
    techniques.push({
      id: 'T1590.001',
      name: 'Domain Properties',
      tactic: 'Reconnaissance',
      parent: 'T1590 · Gather Victim Network Information',
      severity: riskIds.has('new_domain') ? 'high' : 'low',
      description: `WHOIS records for ${domain} are publicly queryable. Registrant history and domain age reveal trust posture and can inform lookalike-domain selection for impersonation campaigns.`,
    })
  }

  return techniques
}

function AttackCard({ report }) {
  const techniques = buildAttackMappings(report)
  if (techniques.length === 0) return null

  return (
    <div
      className="attack-card animate-in"
      role="region"
      aria-label="MITRE ATT&CK technique mappings"
      style={{ animationDelay: '0.1s' }}
    >
      <div className="attack-card-header">
        <div>
          <div className="attack-card-title">🎯 MITRE ATT&CK Mapping</div>
          <div className="attack-card-sub">
            {techniques.length} applicable Reconnaissance technique{techniques.length !== 1 ? 's' : ''} identified from findings
          </div>
        </div>
        <a
          href="https://attack.mitre.org/tactics/TA0043/"
          target="_blank"
          rel="noopener noreferrer"
          className="attack-ref-link"
          aria-label="View TA0043 Reconnaissance tactic on MITRE ATT&CK, opens in new tab"
        >
          TA0043 ↗
        </a>
      </div>

      <div className="attack-technique-list" role="list">
        {techniques.map((t) => (
          <div
            key={t.id}
            className={`attack-technique ${t.severity}`}
            role="listitem"
            tabIndex={0}
            aria-label={`${t.id} ${t.name}, severity ${t.severity}: ${t.description}`}
          >
            <div className="technique-header" aria-hidden="true">
              <span className="technique-id">{t.id}</span>
              <span className="technique-name">{t.name}</span>
              <span className={`technique-severity ${t.severity}`}>{t.severity}</span>
            </div>
            <div className="technique-tactic" aria-hidden="true">
              {t.tactic}{t.parent ? ` · ${t.parent}` : ''}
            </div>
            <div className="technique-desc">{t.description}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function formatScanTime(iso) {
  if (!iso) return null
  const diff = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 10)  return 'just now'
  if (diff < 60)  return `${diff}s ago`
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function formatPrintDate(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
}

export default function Dashboard({ report, onBack }) {
  const data = report
  const [activeView, setActiveView] = useState(data.scan_mode === 'quick' ? 'threat' : 'recruiter')
  const { title, desc } = scoreInfo(data.visibility_score)
  const meta = data.scan_meta
  const platformCount = meta?.platforms_checked?.length ?? null
  const scanTime = formatScanTime(meta?.scanned_at)
  const printSubject = data.full_name || data.username || ''

  return (
    <div className="dashboard">
      <nav className="dash-nav">
        <div className="dash-nav-left">
          <div className="nav-logo">Echo</div>
          <button className="btn-back" onClick={onBack}>← New report</button>
          <button className="btn-print" onClick={() => window.print()}>↓ Export PDF</button>
        </div>
        <div className="view-tabs">
          {Object.entries(VIEW_CONFIG).map(([key, cfg]) => {
            const locked = data.scan_mode === 'quick' && key !== 'threat'
            return (
              <button
                key={key}
                className={`view-tab view-tab--${cfg.theme} ${activeView === key ? 'active' : ''} ${locked ? 'locked' : ''}`}
                onClick={() => !locked && setActiveView(key)}
                title={locked ? 'Run a Deep Scan to unlock this view' : undefined}
                aria-disabled={locked}
                tabIndex={locked ? -1 : undefined}
              >
                {cfg.icon} {cfg.label}
                {locked && <span className="view-tab-lock" aria-hidden="true">🔒</span>}
              </button>
            )
          })}
        </div>
      </nav>

      <div className="print-header" aria-hidden="true">
        <div className="print-header-top">
          <span className="print-logo">Echo</span>
          <span className="print-report-label">Visibility Report</span>
        </div>
        <div className="print-meta">
          {printSubject && <span>Subject: {printSubject}</span>}
          {data.email && <span>{data.email}</span>}
          {data.website && <span>{data.website}</span>}
          <span>Generated {formatPrintDate(meta?.scanned_at) || new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</span>
          <span>{data.scan_mode === 'deep' ? 'Deep Scan' : 'Quick Scan'}{platformCount ? ` · ${platformCount} platforms` : ''}</span>
        </div>
      </div>

      <div className="dash-body">
        {/* Score hero */}
        <div className="score-hero animate-in">
          <div className="score-ring-wrap">
            <ScoreRing score={data.visibility_score} />
          </div>
          <div className="score-details">
            <div className="score-eyebrow">Visibility Score</div>
            <div className={`scan-mode-badge ${data.scan_mode || 'quick'}`}>
              {data.scan_mode === 'deep' ? '🔭 Deep Scan' : '⚡ Quick Scan'}
            </div>
            <div className="score-title">{title}</div>
            <div className="score-desc">{desc}</div>
            <div className="score-meta">
              {(data.full_name || data.username) && (
                <span className="score-meta-item">👤 {data.full_name || data.username}</span>
              )}
              {data.email && <span className="score-meta-item">📧 {data.email}</span>}
              {data.website && <span className="score-meta-item">🌐 {data.website}</span>}
            </div>
            {(platformCount || scanTime) && (
              <div className="scan-meta-bar">
                {platformCount && <span>🔍 {platformCount} platforms checked</span>}
                {meta?.domain_checked && <span>· {meta.domain_checked}</span>}
                {scanTime && <span>· {scanTime}</span>}
              </div>
            )}
          </div>
        </div>

        {/* Cards */}
        <div className="cards-grid">
          <div className="card animate-in" style={{ animationDelay: '0.08s' }}>
            <div className="card-title">⭐ Public Signals</div>
            <div className="signal-list">
              {(data.public_signals || []).map((s) => (
                <div key={s.id} className={`signal-item ${s.detected ? '' : 'absent'}`}>
                  <div className="signal-icon">{s.icon}</div>
                  <span>{s.label}</span>
                  <span className={`signal-dot ${s.detected ? 'found' : 'absent'}`} />
                </div>
              ))}
            </div>
          </div>

          <div className="card animate-in" style={{ animationDelay: '0.16s' }}>
            <div className="card-title">⚠️ Exposure Risks</div>
            <div className="risk-list">
              {(data.exposure_risks || []).map((r) => (
                <div key={r.id} className={`risk-item ${r.severity}`}>
                  <div className="risk-header">
                    <div className="risk-title">{r.title}</div>
                    <div className={`risk-badge ${r.severity}`}>{r.severity}</div>
                  </div>
                  <div className="risk-desc">{r.description}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="card animate-in" style={{ animationDelay: '0.24s' }}>
            <div className="card-title">🧭 Recommended Actions</div>
            <div className="action-list">
              {(data.recommended_actions || []).map((a, i) => (
                <div key={a.id} className="action-item">
                  <div className="action-num">{i + 1}</div>
                  <div>
                    <div className="action-title">{a.title}</div>
                    <div className={`action-priority ${a.priority}`}>{a.priority} priority</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* View panels — active shown on screen, all shown in print */}
        {Object.entries(VIEW_CONFIG).map(([key, cfg]) => {
          const vd = data.views?.[key]
          if (!vd) return null
          const isActive = key === activeView
          return (
            <div
              key={key}
              className={`view-panel view-panel--${cfg.theme}${isActive ? ' animate-in' : ' view-panel--hidden'}`}
              style={isActive ? { animationDelay: '0s' } : undefined}
              aria-hidden={!isActive || undefined}
            >
              <div className="view-panel-header">
                <div>
                  <div className="view-eyebrow">{cfg.label}</div>
                  <div className="view-headline">{vd.headline}</div>
                </div>
                <div className="view-icon">{cfg.icon}</div>
              </div>
              <div className="view-signals-grid">
                {(vd.signals || []).map((s, i) => (
                  <div key={i} className="view-signal">
                    <div className={`sig-indicator ${s.sentiment}`} />
                    <span>{s.label}</span>
                  </div>
                ))}
              </div>
              <div className="view-summary">{vd.summary}</div>
            </div>
          )
        })}

        {/* ATT&CK card — shown on screen in Threat view, always in print for deep scans */}
        {data.scan_mode === 'deep' && (
          <div className={activeView !== 'threat' ? 'print-only' : undefined}>
            <AttackCard report={data} />
          </div>
        )}
      </div>
    </div>
  )
}
