import { useEffect, useRef } from 'react'

const LAYERS = [
  { count: 70, speed: 0.012, minSize: 0.4, maxSize: 0.9, minOpacity: 0.15, maxOpacity: 0.4 },
  { count: 55, speed: 0.025, minSize: 0.9, maxSize: 1.4, minOpacity: 0.25, maxOpacity: 0.55 },
  { count: 30, speed: 0.05,  minSize: 1.4, maxSize: 2.0, minOpacity: 0.35, maxOpacity: 0.7 },
]

function rand(min, max) {
  return min + Math.random() * (max - min)
}

export default function Starfield() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    let raf

    function resize() {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    // Build star pool
    const stars = LAYERS.flatMap(layer =>
      Array.from({ length: layer.count }, () => ({
        x: rand(0, canvas.width),
        y: rand(0, canvas.height),
        size: rand(layer.minSize, layer.maxSize),
        baseOpacity: rand(layer.minOpacity, layer.maxOpacity),
        speed: layer.speed * (0.7 + Math.random() * 0.6),
        drift: (Math.random() - 0.5) * 0.008,
        twinkleSpeed: rand(0.004, 0.012),
        twinklePhase: rand(0, Math.PI * 2),
      }))
    )

    // Shooting star pool
    const shooters = []

    let frame = 0

    function maybeSpawnShooter() {
      if (shooters.length < 2 && Math.random() < 0.0015) {
        const angle = rand(20, 40) * (Math.PI / 180)
        const speed = rand(6, 11)
        shooters.push({
          x: rand(canvas.width * 0.1, canvas.width * 0.9),
          y: rand(0, canvas.height * 0.4),
          vx: Math.cos(angle) * speed,
          vy: Math.sin(angle) * speed,
          length: rand(60, 120),
          life: 1,
          decay: rand(0.016, 0.028),
        })
      }
    }

    function drawShooter(ss) {
      const nx = ss.vx / Math.hypot(ss.vx, ss.vy)
      const ny = ss.vy / Math.hypot(ss.vx, ss.vy)
      const grad = ctx.createLinearGradient(
        ss.x, ss.y,
        ss.x - nx * ss.length, ss.y - ny * ss.length
      )
      grad.addColorStop(0, `rgba(220, 230, 255, ${ss.life * 0.9})`)
      grad.addColorStop(1, 'rgba(220, 230, 255, 0)')
      ctx.beginPath()
      ctx.strokeStyle = grad
      ctx.lineWidth = 1.2
      ctx.moveTo(ss.x, ss.y)
      ctx.lineTo(ss.x - nx * ss.length, ss.y - ny * ss.length)
      ctx.stroke()
    }

    function tick() {
      ctx.clearRect(0, 0, canvas.width, canvas.height)
      frame++

      // Stars
      for (const s of stars) {
        s.y += s.speed
        s.x += s.drift
        if (s.y > canvas.height) { s.y = 0; s.x = rand(0, canvas.width) }
        if (s.x < 0) s.x = canvas.width
        if (s.x > canvas.width) s.x = 0

        const twinkle = 0.65 + 0.35 * Math.sin(frame * s.twinkleSpeed + s.twinklePhase)
        const alpha = s.baseOpacity * twinkle

        ctx.beginPath()
        ctx.arc(s.x, s.y, s.size, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(210, 225, 255, ${alpha})`
        ctx.fill()

        // Soft glow halo on larger stars
        if (s.size > 1.5 && twinkle > 0.85) {
          ctx.beginPath()
          ctx.arc(s.x, s.y, s.size * 3, 0, Math.PI * 2)
          ctx.fillStyle = `rgba(160, 200, 255, ${alpha * 0.12})`
          ctx.fill()
        }
      }

      // Shooting stars
      maybeSpawnShooter()
      for (let i = shooters.length - 1; i >= 0; i--) {
        const ss = shooters[i]
        drawShooter(ss)
        ss.x += ss.vx
        ss.y += ss.vy
        ss.life -= ss.decay
        if (ss.life <= 0) shooters.splice(i, 1)
      }

      raf = requestAnimationFrame(tick)
    }

    tick()

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        inset: 0,
        pointerEvents: 'none',
        zIndex: 1,
        opacity: 0.5,
      }}
    />
  )
}
