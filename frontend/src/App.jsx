import React, { useState } from 'react'
import Landing from './components/Landing'
import Dashboard from './components/Dashboard'
import Starfield from './components/Starfield'

export default function App() {
  const [view, setView] = useState('landing')
  const [report, setReport] = useState(null)
  const [phase, setPhase] = useState('idle') // 'idle' | 'exiting' | 'entering'

  function navigate(nextView, nextReport = null) {
    setPhase('exiting')
    setTimeout(() => {
      if (nextReport) setReport(nextReport)
      setView(nextView)
      setPhase('entering')
      setTimeout(() => setPhase('idle'), 480)
    }, 300)
  }

  return (
    <div className="app-root">
      <Starfield />
      <div className={`page-wrap page-${phase}`}>
        {view === 'landing' && (
          <Landing onGenerate={(r) => navigate('dashboard', r)} />
        )}
        {view === 'dashboard' && (
          <Dashboard report={report} onBack={() => navigate('landing')} />
        )}
      </div>
    </div>
  )
}
