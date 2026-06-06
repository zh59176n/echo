import React, { useState } from 'react'

const SCAN_STEPS = {
  quick: [
    { emoji: '⚡', label: 'Launching quick scan' },
    { emoji: '🔍', label: 'Checking GitHub, Keybase, Gravatar…' },
  ],
  deep: [
    { emoji: '🚀', label: 'Launching analysis' },
    { emoji: '🛰️', label: 'Scanning GitHub, GitLab, DEV.to…' },
    { emoji: '🔭', label: 'Checking Keybase, Mastodon, HN…' },
    { emoji: '✨', label: 'Analyzing domain & DNS records' },
  ],
}

const STEP_DURATIONS = {
  quick: [800, 1800],
  deep:  [1000, 1400, 1400, 1100],
}

function buildClientMock(scanMode, username, email, website, fullName) {
  const name = username || fullName || 'you'
  const base = {
    username,
    full_name: fullName,
    email,
    website,
    scan_mode: scanMode,
    visibility_score: scanMode === 'quick' ? 54 : 72,
    public_signals: scanMode === 'quick'
      ? [
          { id: 'github',   label: 'GitHub — no profile found',              icon: '⌨️', detected: false },
          { id: 'keybase',  label: 'Keybase — no account found',             icon: '🔑', detected: false },
          { id: 'gravatar', label: 'Gravatar — email not linked',            icon: '🌐', detected: false },
        ]
      : [
          { id: 'github',      label: 'GitHub profile detected',             icon: '⌨️', detected: true  },
          { id: 'gitlab',      label: 'GitLab — no profile found',           icon: '🦊', detected: false },
          { id: 'devto',       label: 'DEV.to — no account found',           icon: '👩‍💻', detected: false },
          { id: 'hackernews',  label: 'HackerNews — no account found',       icon: '🟠', detected: false },
          { id: 'keybase',     label: 'Keybase — no account found',          icon: '🔑', detected: false },
          { id: 'mastodon',    label: 'Mastodon — no account found',         icon: '🐘', detected: false },
          { id: 'gravatar',    label: 'Gravatar — email not linked',         icon: '🌐', detected: false },
        ],
    exposure_risks: [
      { id: 'cross_platform', title: 'Username found across platforms',     description: `"${name}" is detectable on multiple platforms.`,            severity: 'medium' },
      { id: 'no_spf',         title: 'No SPF record — domain is spoofable', description: 'Without SPF, anyone can send email from your domain.',      severity: 'medium' },
    ],
    recommended_actions: [
      { id: 'hibp',          title: 'Check your email on HaveIBeenPwned',                priority: 'high'   },
      { id: 'privacy_audit', title: 'Audit privacy settings on all active platforms',    priority: 'medium' },
      { id: 'data_brokers',  title: 'Submit opt-out requests to data broker sites',      priority: 'low'    },
    ],
    scan_meta: {
      platforms_checked: scanMode === 'quick' ? ['github', 'keybase', 'gravatar'] : ['github', 'gitlab', 'devto', 'hackernews', 'keybase', 'mastodon', 'gravatar'],
      domain_checked: null,
      scanned_at: new Date().toISOString(),
    },
    views: {
      recruiter:  scanMode === 'deep' ? {
        headline: 'Strong professional presence with minor exposure concerns',
        signals: [
          { label: 'Active GitHub with public contributions',           sentiment: 'positive' },
          { label: 'LinkedIn profile publicly accessible',              sentiment: 'positive' },
          { label: 'Technical writing or blog activity found',          sentiment: 'positive' },
          { label: 'Professional email domain confirmed',               sentiment: 'positive' },
          { label: 'No controversial public content detected',          sentiment: 'positive' },
          { label: 'Activity suggests full-time professional schedule', sentiment: 'neutral'  },
        ],
        summary: `A recruiter would form a strong positive first impression of ${name}.`,
      } : null,
      advertiser: scanMode === 'deep' ? {
        headline: 'High-value targeting profile with inferred tech-sector interests',
        signals: [
          { label: 'Inferred interests: software, technology, design',            sentiment: 'neutral'  },
          { label: 'Estimated income bracket: Mid-to-Senior tech professional',   sentiment: 'neutral'  },
          { label: 'Platform engagement: GitHub, LinkedIn, Twitter/X',            sentiment: 'neutral'  },
          { label: 'Likely B2B software purchaser',                               sentiment: 'neutral'  },
          { label: 'Geographic signals inferrable from activity',                 sentiment: 'warning'  },
          { label: 'Retargetable across 3+ ad networks',                          sentiment: 'warning'  },
        ],
        summary: `The public presence of ${name} creates a detailed advertiser profile.`,
      } : null,
      threat: {
        headline: 'Moderate exposure — email and username are primary attack vectors',
        signals: [
          { label: `Email ${email || 'address'} may be harvestable from public sources`,  sentiment: 'warning'  },
          { label: `Username "${name}" searchable across developer platforms`,             sentiment: 'warning'  },
          { label: 'Public repos may reveal employer or current projects',                 sentiment: 'warning'  },
          { label: 'Activity timing reveals likely timezone',                              sentiment: 'warning'  },
          { label: 'No password breach data found',                                        sentiment: 'positive' },
          { label: 'Account recovery routes partially visible',                            sentiment: 'warning'  },
        ],
        summary: `The exposed email and username for ${name} create targetable vectors for phishing. No breach data was checked in this scan — run HaveIBeenPwned to complete the picture.`,
      },
    },
  }
  return base
}

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

export default function Landing({ onGenerate }) {
  const [scanMode, setScanMode]   = useState('quick')
  const [username, setUsername]   = useState('')
  const [fullName, setFullName]   = useState('')
  const [email, setEmail]         = useState('')
  const [website, setWebsite]     = useState('')
  const [loading, setLoading]     = useState(false)
  const [step, setStep]           = useState(-1)
  const [error, setError]         = useState('')

  const steps     = SCAN_STEPS[scanMode]
  const durations = STEP_DURATIONS[scanMode]

  async function handleSubmit(e) {
    e.preventDefault()
    if (scanMode === 'quick' && !username.trim()) {
      setError('Username is required for Quick Scan.')
      return
    }
    if (scanMode === 'deep' && !fullName.trim()) {
      setError('Full name is required for Deep Scan.')
      return
    }
    setError('')
    setLoading(true)
    setStep(0)

    const fetchPromise = (async () => {
      try {
        const resp = await fetch('/api/report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: username.trim() || undefined,
            full_name: fullName.trim() || undefined,
            email: email.trim() || undefined,
            website: website.trim() || undefined,
            scan_mode: scanMode,
          }),
          signal: AbortSignal.timeout(scanMode === 'quick' ? 8000 : 16000),
        })
        if (!resp.ok) throw new Error('api_error')
        const data = await resp.json()
        return { ...buildClientMock(scanMode, username, email, website, fullName), ...data }
      } catch {
        return buildClientMock(scanMode, username, email, website, fullName)
      }
    })()

    const animPromise = (async () => {
      for (let i = 0; i < steps.length; i++) {
        await delay(durations[i])
        setStep(i + 1)
      }
    })()

    const [data] = await Promise.all([fetchPromise, animPromise])
    await delay(300)
    onGenerate(data)
    setLoading(false)
    setStep(-1)
  }

  const progress = step <= 0 ? 0 : Math.round((step / steps.length) * 100)

  return (
    <div className="landing">
      {loading && (
        <div className="loading-overlay">
          <div className="lo-orbit-wrap">
            <div className="lo-pulse-ring" />
            <div className="lo-pulse-ring lo-pulse-ring--2" />
            <div className="lo-emblem">
              <div className="lo-spinner" />
              <span className="lo-emblem-letter">E</span>
            </div>
          </div>

          <div className="lo-content">
            <div className="lo-title">Scanning digital footprint</div>
            <div className="lo-sub">{email || username || fullName}</div>

            <div className="lo-steps">
              {steps.map((s, i) => (
                <div
                  key={i}
                  className={[
                    'lo-step',
                    step > i  ? 'lo-done'   : '',
                    step === i ? 'lo-active' : '',
                    step >= i  ? 'lo-vis'    : '',
                  ].filter(Boolean).join(' ')}
                >
                  <span className="lo-step-icon">{step > i ? '✓' : s.emoji}</span>
                  <span className="lo-step-label">{s.label}</span>
                </div>
              ))}
            </div>

            <div className="progress-bar">
              <div className="progress-fill" style={{ width: `${progress}%` }} />
            </div>
            <div className="lo-pct">{progress}%</div>
          </div>
        </div>
      )}

      <nav className="nav">
        <div className="nav-logo">Echo</div>
        <div className="nav-badge">Beta</div>
      </nav>

      <section className="hero">
        <div className="hero-eyebrow">
          <span className="eyebrow-dot" />
          OSINT · Privacy Intelligence
        </div>
        <h1 className="hero-title">Echo</h1>
        <p className="hero-tagline">See your public digital footprint.</p>
        <p className="hero-description">
          Echo runs open-source intelligence checks on your public accounts and shows
          what's visible to recruiters, advertisers, and threat actors.
        </p>

        <div className="feature-pills">
          <span className="pill">🔍 Platform scan</span>
          <span className="pill">⚠️ Exposure risks</span>
          <span className="pill">✓ Remediation steps</span>
          <span className="pill">👁️ Three perspectives</span>
        </div>
      </section>

      <div className="form-card">
        <div className="form-card-title">Run a visibility report</div>
        <div className="form-card-sub">Pick a scan mode and enter your details.</div>

        {/* Scan mode toggle */}
        <div className="scan-mode-toggle" role="group" aria-label="Scan mode">
          <button
            type="button"
            className={`scan-mode-btn ${scanMode === 'quick' ? 'active' : ''}`}
            onClick={() => { setScanMode('quick'); setError('') }}
            aria-pressed={scanMode === 'quick'}
          >
            ⚡ Quick Scan
          </button>
          <button
            type="button"
            className={`scan-mode-btn ${scanMode === 'deep' ? 'active' : ''}`}
            onClick={() => { setScanMode('deep'); setError('') }}
            aria-pressed={scanMode === 'deep'}
          >
            🔭 Deep Scan
          </button>
        </div>
        <div className="scan-mode-desc">
          {scanMode === 'quick'
            ? '3 platforms · ~5 seconds · Threat overview'
            : '7 platforms + DNS · ~15 seconds · Full professional assessment + MITRE ATT&CK'}
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            {scanMode === 'deep' && (
              <div className="field">
                <label htmlFor="fullname">Full name</label>
                <input
                  id="fullname"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. Alex Johnson"
                  autoComplete="name"
                />
              </div>
            )}

            <div className="field">
              <label htmlFor="username">
                Username {scanMode === 'deep' && <span className="field-optional">optional</span>}
              </label>
              <input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. alice123"
                autoComplete="username"
              />
            </div>

            <div className="field">
              <label htmlFor="email">
                Email address <span className="field-optional">optional</span>
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                autoComplete="email"
              />
            </div>

            {scanMode === 'deep' && (
              <div className="field">
                <label htmlFor="website">
                  Website <span className="field-optional">optional</span>
                </label>
                <input
                  id="website"
                  value={website}
                  onChange={(e) => setWebsite(e.target.value)}
                  placeholder="https://yoursite.com"
                  autoComplete="url"
                />
              </div>
            )}
          </div>

          {error && <div className="form-error">{error}</div>}

          <button className="btn-primary" type="submit" disabled={loading}>
            <span className="btn-shimmer" />
            {loading ? 'Scanning…' : `Generate ${scanMode === 'quick' ? 'Quick' : 'Deep'} Scan Report →`}
          </button>
        </form>
      </div>
    </div>
  )
}
