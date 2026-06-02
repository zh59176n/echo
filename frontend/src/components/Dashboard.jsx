import React, { useState, useEffect } from 'react'

const VIEW_CONFIG = {
  recruiter: { label: 'Recruiter View', icon: '👔' },
  advertiser: { label: 'Advertiser View', icon: '📢' },
  threat: { label: 'Threat Actor View', icon: '🎣' },
}

function ScoreRing({ score }) {
  const [animated, setAnimated] = useState(false)

  useEffect(() => {
    const t = setTimeout(() => setAnimated(true), 120)
    return () => clearTimeout(t)
  }, [])

  const r = 50
  const circ = 2 * Math.PI * r
  const filled = animated ? (score / 100) * circ : 0

  return (
    <svg width="148" height="148" viewBox="0 0 116 116" style={{ display: 'block' }}>
      <defs>
        <linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#818cf8" />
          <stop offset="100%" stopColor="#22d3ee" />
        </linearGradient>
      </defs>
      <circle
        cx="58" cy="58" r={r}
        fill="none"
        stroke="rgba(255,255,255,0.06)"
        strokeWidth="7"
      />
      <circle
        cx="58" cy="58" r={r}
        fill="none"
        stroke="url(#scoreGrad)"
        strokeWidth="7"
        strokeLinecap="round"
        strokeDasharray={`${filled} ${circ}`}
        style={{
          transform: 'rotate(-90deg)',
          transformOrigin: '50% 50%',
          transition: 'stroke-dasharray 1.5s cubic-bezier(0.4, 0, 0.2, 1)',
        }}
      />
      <text
        x="58" y="52"
        textAnchor="middle"
        fill="#f1f5f9"
        fontSize="26"
        fontWeight="700"
        fontFamily="Inter, sans-serif"
      >
        {score}
      </text>
      <text
        x="58" y="68"
        textAnchor="middle"
        fill="#64748b"
        fontSize="11"
        fontFamily="Inter, sans-serif"
      >
        / 100
      </text>
    </svg>
  )
}

function scoreLabel(score) {
  if (score >= 80) return { title: 'Highly Visible', desc: 'Your digital footprint is very extensive. Multiple platforms expose significant personal information about you.' }
  if (score >= 60) return { title: 'Moderately Visible', desc: 'Your presence is detectable across several platforms. Some exposure risks warrant your attention.' }
  if (score >= 40) return { title: 'Low Visibility', desc: 'Your digital footprint is relatively contained. A few minor exposure points were detected.' }
  return { title: 'Minimal Visibility', desc: 'Very limited public digital presence detected. Your overall privacy posture is strong.' }
}

export default function Dashboard({ report, onBack }) {
  const [activeView, setActiveView] = useState('recruiter')
  const data = report
  const { title, desc } = scoreLabel(data.visibility_score)
  const viewData = data.views?.[activeView]

  return (
    <div className="dashboard">
      <nav className="dash-nav">
        <div className="dash-nav-left">
          <div className="nav-logo">Echo</div>
          <button className="btn-back" onClick={onBack}>← New report</button>
        </div>
        <div className="view-tabs">
          {Object.entries(VIEW_CONFIG).map(([key, cfg]) => (
            <button
              key={key}
              className={`view-tab ${activeView === key ? 'active' : ''}`}
              onClick={() => setActiveView(key)}
            >
              {cfg.icon} {cfg.label}
            </button>
          ))}
        </div>
      </nav>

      <div className="dash-body">
        {/* Score Hero */}
        <div className="score-hero animate-in">
          <div className="score-ring-wrap">
            <ScoreRing score={data.visibility_score} />
          </div>
          <div className="score-details">
            <div className="score-eyebrow">Visibility Score</div>
            <div className="score-title">{title}</div>
            <div className="score-desc">{desc}</div>
            <div className="score-meta">
              <span className="score-meta-item">👤 {data.username}</span>
              <span className="score-meta-item">📧 {data.email}</span>
              {data.website && (
                <span className="score-meta-item">🌐 {data.website}</span>
              )}
            </div>
          </div>
        </div>

        {/* Cards Grid */}
        <div className="cards-grid">
          {/* Public Signals */}
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

          {/* Exposure Risks */}
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

          {/* Recommended Actions */}
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

        {/* View Panel */}
        {viewData && (
          <div key={activeView} className="view-panel animate-in" style={{ animationDelay: '0.32s' }}>
            <div className="view-panel-header">
              <div>
                <div className="view-eyebrow">{VIEW_CONFIG[activeView].label}</div>
                <div className="view-headline">{viewData.headline}</div>
              </div>
              <div className="view-icon">{VIEW_CONFIG[activeView].icon}</div>
            </div>

            <div className="view-signals-grid">
              {(viewData.signals || []).map((s, i) => (
                <div key={i} className="view-signal">
                  <div className={`sig-indicator ${s.sentiment}`} />
                  <span>{s.label}</span>
                </div>
              ))}
            </div>

            <div className="view-summary">{viewData.summary}</div>
          </div>
        )}
      </div>
    </div>
  )
}
