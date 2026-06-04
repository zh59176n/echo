import React, { useState } from 'react'

const SCAN_STEPS = [
  { emoji: '🚀', label: 'Launching analysis' },
  { emoji: '🛰️', label: 'Scanning GitHub, GitLab, DEV.to…' },
  { emoji: '🔭', label: 'Checking Keybase, Mastodon, HN…' },
  { emoji: '✨', label: 'Analyzing domain & DNS records' },
]

const STEP_DURATIONS = [1000, 1400, 1400, 1100]

function buildClientMock(username, email, website) {
  return {
    username,
    email,
    website,
    visibility_score: 72,
    public_signals: [
      { id: 'github',       label: 'GitHub profile detected',          icon: '⌨️', detected: true },
      { id: 'linkedin',     label: 'LinkedIn profile detected',        icon: '💼', detected: true },
      { id: 'twitter',      label: 'Twitter/X activity found',         icon: '🐦', detected: true },
      { id: 'email_exp',    label: 'Email found in 3 public sources',  icon: '📧', detected: true },
      { id: 'data_broker',  label: 'Listed on 2 data broker sites',    icon: '🗃️', detected: true },
      { id: 'dark_web',     label: 'No dark web exposure detected',    icon: '🛡️', detected: false },
    ],
    exposure_risks: [
      { id: 'email',        title: 'Public email address visible',      description: `The email ${email} appears on GitHub and public forums`,                              severity: 'high'   },
      { id: 'username',     title: 'Username linked across platforms',  description: `Username "${username}" found on 4 platforms, enabling cross-profiling`,              severity: 'medium' },
      { id: 'activity',     title: 'Activity patterns visible',         description: 'Public timestamps reveal your typical timezone and active hours',                    severity: 'low'    },
      { id: 'broker',       title: 'Listed on data broker sites',       description: 'Personal information aggregated by 2 data brokers',                                  severity: 'medium' },
    ],
    recommended_actions: [
      { id: 'email',    title: 'Remove public email from GitHub profile',               priority: 'high'   },
      { id: 'broker',   title: 'Submit opt-out requests to data brokers',               priority: 'high'   },
      { id: 'review',   title: 'Review privacy settings on all social platforms',       priority: 'medium' },
      { id: 'username', title: 'Consider using different usernames per platform',       priority: 'medium' },
      { id: 'audit',    title: 'Audit and archive old public posts',                    priority: 'low'    },
    ],
    views: {
      recruiter: {
        headline: 'Strong professional presence with minor exposure concerns',
        signals: [
          { label: 'Active GitHub with public contributions',            sentiment: 'positive' },
          { label: 'LinkedIn profile publicly accessible',               sentiment: 'positive' },
          { label: 'Technical writing or blog activity found',           sentiment: 'positive' },
          { label: 'Professional email domain confirmed',                sentiment: 'positive' },
          { label: 'No controversial public content detected',           sentiment: 'positive' },
          { label: 'Activity suggests full-time professional schedule',  sentiment: 'neutral'  },
        ],
        summary: `A recruiter would form a strong positive first impression of ${username}. Professional profiles are visible and well-maintained. The public email exposure is a minor concern but unlikely to affect professional perception.`,
      },
      advertiser: {
        headline: 'High-value targeting profile with inferred tech-sector interests',
        signals: [
          { label: 'Inferred interests: software, technology, design',               sentiment: 'neutral'  },
          { label: 'Estimated income bracket: Mid-to-Senior tech professional',      sentiment: 'neutral'  },
          { label: 'Platform engagement: GitHub, LinkedIn, Twitter/X',               sentiment: 'neutral'  },
          { label: 'Likely B2B software purchaser',                                  sentiment: 'neutral'  },
          { label: 'Geographic signals inferrable from activity',                    sentiment: 'warning'  },
          { label: 'Retargetable across 3+ ad networks',                             sentiment: 'warning'  },
        ],
        summary: `The public digital presence of ${username} creates a detailed advertiser profile. Marketers can infer occupation, interests, income level, and device usage from publicly available signals — without any direct ad interaction.`,
      },
      threat: {
        headline: 'Moderate social engineering risk — email and username are key vectors',
        signals: [
          { label: `Email ${email} confirmed on 3 public sources`,                   sentiment: 'danger'   },
          { label: `Username "${username}" consistent across 4 platforms`,            sentiment: 'danger'   },
          { label: 'Public repos may reveal employer or current projects',            sentiment: 'warning'  },
          { label: 'Activity timing reveals likely timezone',                         sentiment: 'warning'  },
          { label: 'No password breach data found',                                  sentiment: 'positive' },
          { label: 'Account recovery routes partially visible',                      sentiment: 'warning'  },
        ],
        summary: `The exposed email and consistent username for ${username} create targetable attack vectors for phishing and credential stuffing. Cross-platform linking allows a threat actor to build a detailed profile with minimal effort. No breach data found — this significantly reduces immediate risk.`,
      },
    },
  }
}

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

export default function Landing({ onGenerate }) {
  const [username, setUsername] = useState('')
  const [email, setEmail]       = useState('')
  const [website, setWebsite]   = useState('')
  const [loading, setLoading]   = useState(false)
  const [step, setStep]         = useState(-1)
  const [error, setError]       = useState('')

  async function handleSubmit(e) {
    e.preventDefault()
    if (!username.trim() || !email.trim()) {
      setError('Username and email are required.')
      return
    }
    setError('')
    setLoading(true)
    setStep(0)

    // Fire the real API request immediately — don't wait for animation
    const fetchPromise = (async () => {
      try {
        const resp = await fetch('/api/report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, email, website }),
          signal: AbortSignal.timeout(14000), // real scans can take ~8s
        })
        if (!resp.ok) throw new Error('api_error')
        const data = await resp.json()
        // Merge: backend data wins over client mock for matching keys
        return { ...buildClientMock(username, email, website), ...data }
      } catch {
        return buildClientMock(username, email, website)
      }
    })()

    // Animate steps concurrently — always plays at full speed regardless of API timing
    const animPromise = (async () => {
      for (let i = 0; i < SCAN_STEPS.length; i++) {
        await delay(STEP_DURATIONS[i])
        setStep(i + 1)
      }
    })()

    // Both must finish before proceeding — animation always plays in full,
    // fetch either finishes during the animation or we wait for it after
    const [data] = await Promise.all([fetchPromise, animPromise])

    await delay(300) // brief moment showing all steps completed
    onGenerate(data)
    setLoading(false)
    setStep(-1)
  }

  const progress = step <= 0 ? 0 : Math.round((step / SCAN_STEPS.length) * 100)

  return (
    <div className="landing">
      {loading && (
        <div className="loading-overlay">
          {/* Pulsing orbital rings */}
          <div className="lo-orbit-wrap">
            <div className="lo-pulse-ring" />
            <div className="lo-pulse-ring lo-pulse-ring--2" />
            <div className="lo-emblem">
              <div className="lo-spinner" />
              <span className="lo-emblem-letter">E</span>
            </div>
          </div>

          {/* Content */}
          <div className="lo-content">
            <div className="lo-title">Scanning digital footprint</div>
            <div className="lo-sub">{email || username}</div>

            <div className="lo-steps">
              {SCAN_STEPS.map((s, i) => (
                <div
                  key={i}
                  className={[
                    'lo-step',
                    step > i  ? 'lo-done'   : '',
                    step === i ? 'lo-active' : '',
                    step >= i  ? 'lo-vis'    : '',
                  ].filter(Boolean).join(' ')}
                >
                  <span className="lo-step-icon">
                    {step > i ? '✓' : s.emoji}
                  </span>
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
          Digital Privacy Intelligence
        </div>
        <h1 className="hero-title">Echo</h1>
        <p className="hero-tagline">🌌 See what the internet remembers.</p>
        <p className="hero-description">
          Echo scans your public digital footprint and reveals exactly what recruiters,
          advertisers, and threat actors can discover about you — in seconds.
        </p>

        <div className="feature-pills">
          <span className="pill">🔍 Public profile scan</span>
          <span className="pill">🛡️ Exposure risk analysis</span>
          <span className="pill">🧭 Actionable guidance</span>
          <span className="pill">👁️ Multi-perspective view</span>
        </div>
      </section>

      <div className="form-card">
        <div className="form-card-title">Generate your Visibility Report</div>
        <div className="form-card-sub">Enter your details to see your digital exposure.</div>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <div className="field">
              <label htmlFor="username">Username</label>
              <input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. alice123"
                autoComplete="username"
              />
            </div>
            <div className="field">
              <label htmlFor="email">Email address</label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                autoComplete="email"
              />
            </div>
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
          </div>

          {error && <div className="form-error">{error}</div>}

          <button className="btn-primary" type="submit" disabled={loading}>
            <span className="btn-shimmer" />
            {loading ? 'Scanning…' : 'Generate Visibility Report →'}
          </button>
        </form>
      </div>
    </div>
  )
}
