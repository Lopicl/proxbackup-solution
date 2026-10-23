// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef, useState } from 'react'
import { bytes } from './ui'

// Small SVG charts for the dashboard. One series each, in --series.

/** Tracks the rendered width of an element. */
function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null)
  const [width, setWidth] = useState(0)
  useEffect(() => {
    if (!ref.current) return
    const ro = new ResizeObserver(([e]) => setWidth(e.contentRect.width))
    ro.observe(ref.current)
    return () => ro.disconnect()
  }, [])
  return [ref, width] as const
}

const tickFormat: Record<string, Intl.DateTimeFormatOptions> = {
  day: { hour: '2-digit', minute: '2-digit' },
  week: { weekday: 'short', day: 'numeric' },
  month: { day: 'numeric', month: 'short' },
  year: { month: 'short', year: '2-digit' },
}

/** Round byte ticks: steps of 1, 2, 2.5 or 5 times a power of ten in the axis unit (KiB, MiB, GiB…). */
function byteTicks(max: number): number[] {
  const unit = 1024 ** Math.max(0, Math.floor(Math.log(max) / Math.log(1024)))
  const raw = max / 4 / unit
  const mag = 10 ** Math.floor(Math.log10(raw))
  const step = ([1, 2, 2.5, 5, 10].find((f) => f * mag >= raw) ?? 10) * mag * unit
  return Array.from({ length: Math.ceil(max / step - 1e-9) + 1 }, (_, i) => i * step)
}

const pct = (used: number, total: number) => (total ? `${((100 * used) / total).toFixed(1)}%` : '—')

/** Datastore usage over time: used space as an area, capacity as a dashed line. */
export function UsageChart({ points, timeframe }: { points: { t: number; used: number; total: number }[]; timeframe: string }) {
  const [ref, width] = useWidth<HTMLDivElement>()
  const [hover, setHover] = useState<number | null>(null)
  const height = 200
  const m = { top: 12, right: 12, bottom: 24, left: 64 }
  if (points.length < 2) return <div className="chart-empty">Not enough history yet.</div>
  const w = Math.max(0, width - m.left - m.right)
  const h = height - m.top - m.bottom
  const t0 = points[0].t
  const t1 = points[points.length - 1].t
  const yTicks = byteTicks(Math.max(...points.map((p) => Math.max(p.total, p.used))) || 1)
  const max = yTicks[yTicks.length - 1]
  const x = (t: number) => m.left + ((t - t0) / (t1 - t0 || 1)) * w
  const y = (v: number) => m.top + h - (v / max) * h
  const line = points.map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p.used).toFixed(1)}`).join('')
  const area = `${line}L${x(t1).toFixed(1)},${y(0)}L${x(t0).toFixed(1)},${y(0)}Z`
  const cap = points.map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p.total).toFixed(1)}`).join('')
  const xTicks = Array.from({ length: 5 }, (_, i) => t0 + ((t1 - t0) * i) / 4)
  const fmt = new Intl.DateTimeFormat(undefined, tickFormat[timeframe] ?? tickFormat.week)
  const hp = hover !== null ? points[hover] : null
  const last = points[points.length - 1]

  const onMove = (e: React.PointerEvent<SVGRectElement>) => {
    const r = e.currentTarget.getBoundingClientRect()
    const t = t0 + ((e.clientX - r.left) / r.width) * (t1 - t0)
    let best = 0
    for (let i = 1; i < points.length; i++) if (Math.abs(points[i].t - t) < Math.abs(points[best].t - t)) best = i
    setHover(best)
  }

  return (
    <div className="chart" ref={ref}>
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label="Datastore usage over time">
          {yTicks.map((v, i) => (
            <g key={i}>
              <line className="grid" x1={m.left} x2={m.left + w} y1={y(v)} y2={y(v)} />
              <text className="axis" x={m.left - 8} y={y(v)} dy="0.32em" textAnchor="end">
                {bytes(v).replace(".0 ", " ")}
              </text>
            </g>
          ))}
          {xTicks.map((t, i) => (
            <text key={i} className="axis" x={x(t)} y={height - 6} textAnchor={i === 0 ? 'start' : i === 4 ? 'end' : 'middle'}>
              {fmt.format(new Date(t * 1000))}
            </text>
          ))}
          <path className="cap" d={cap} />
          <text className="axis" x={m.left + w} y={y(last.total) - 5} textAnchor="end">
            Capacity
          </text>
          <path className="area" d={area} />
          <path className="line" d={line} />
          {hp && (
            <>
              <line className="crosshair" x1={x(hp.t)} x2={x(hp.t)} y1={m.top} y2={m.top + h} />
              <circle className="marker" cx={x(hp.t)} cy={y(hp.used)} r={4.5} />
            </>
          )}
          <rect
            x={m.left}
            y={m.top}
            width={w}
            height={h}
            fill="transparent"
            onPointerMove={onMove}
            onPointerLeave={() => setHover(null)}
          />
        </svg>
      )}
      {hp && (
        <div className="tooltip" style={{ left: Math.min(x(hp.t) + 12, width - 190), top: m.top }}>
          <div className="muted-text">{new Date(hp.t * 1000).toLocaleString()}</div>
          <div>
            <b>{bytes(hp.used)}</b> used of {bytes(hp.total)}
          </div>
          <div className="muted-text">{pct(hp.used, hp.total)} full</div>
        </div>
      )}
    </div>
  )
}

/** A horizontal meter of used space against capacity, in status colors past 80% and 90%. */
export function UsageMeter({ used, total }: { used: number; total: number }) {
  const f = total ? used / total : 0
  const tone = f >= 0.9 ? 'bad' : f >= 0.8 ? 'warn' : ''
  return (
    <div className="meter-wrap">
      <div className={`meter ${tone}`} role="meter" aria-valuenow={Math.round(100 * f)} aria-valuemin={0} aria-valuemax={100}>
        <div style={{ width: `${Math.min(100, 100 * f)}%` }} />
      </div>
      <div className="meter-label">
        <span>
          <b>{bytes(used)}</b> used of {bytes(total)} ({pct(used, total)})
          {tone && <span className={`${tone}-text`}> · {tone === 'bad' ? 'almost full' : 'filling up'}</span>}
        </span>
        <span className="muted-text">{bytes(total - used)} free</span>
      </div>
    </div>
  )
}

/** Labeled horizontal bars, largest first; the first `limit` are shown until expanded. */
export function BarList({
  items,
  limit = 8,
}: {
  items: { key: number; label: React.ReactNode; value: number; title: string }[]
  limit?: number
}) {
  const [all, setAll] = useState(false)
  const max = Math.max(...items.map((i) => i.value)) || 1
  const shown = all ? items : items.slice(0, limit)
  return (
    <div className="bars">
      {shown.map((i) => (
        <div className="bar-row" key={i.key} title={i.title}>
          <div className="bar-label">{i.label}</div>
          <div className="bar-track">
            <div className="bar" style={{ width: `${(100 * i.value) / max}%` }} />
          </div>
          <div className="bar-value">{bytes(i.value)}</div>
        </div>
      ))}
      {items.length > limit && (
        <button className="ghost small show-more" onClick={() => setAll(!all)}>
          {all ? 'Show fewer' : `Show all ${items.length}`}
        </button>
      )}
    </div>
  )
}
