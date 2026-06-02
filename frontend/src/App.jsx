import React, { useState } from 'react'
import Landing from './components/Landing'
import Dashboard from './components/Dashboard'

export default function App() {
  const [view, setView] = useState('landing')
  const [report, setReport] = useState(null)

  return (
    <div className="app-root">
      {view === 'landing' && (
        <Landing
          onGenerate={(r) => {
            setReport(r)
            setView('dashboard')
          }}
        />
      )}
      {view === 'dashboard' && (
        <Dashboard report={report} onBack={() => setView('landing')} />
      )}
    </div>
  )
}
