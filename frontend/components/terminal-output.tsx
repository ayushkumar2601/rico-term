"use client"

import { useEffect, useRef, useState, useCallback } from "react"
import type { TerminalLine } from "@/lib/terminal-messages"

/**
 * TerminalOutput renders an animated terminal-style display.
 *
 * Lines appear one by one with configurable delays, simulating Rico's
 * AI workflow running in real time.
 *
 * BACKEND INTEGRATION:
 * To stream real scan results, replace the timer-based animation with a
 * ReadableStream / SSE consumer. Each incoming event would be pushed to
 * `visibleLines` via setState, producing the same line-by-line effect
 * but with real data from the Rico engine.
 */

interface TerminalOutputProps {
  /** The full sequence of lines to animate through */
  lines: TerminalLine[]
  /** Called when all lines have been rendered */
  onComplete: () => void
}

const lineColors: Record<string, string> = {
  info: "text-foreground",
  success: "text-primary",
  warning: "text-warning",
  error: "text-destructive",
  dim: "text-muted-foreground",
}

export function TerminalOutput({ lines, onComplete }: TerminalOutputProps) {
  const [visibleCount, setVisibleCount] = useState(0)
  const containerRef = useRef<HTMLDivElement>(null)
  const onCompleteRef = useRef(onComplete)
  onCompleteRef.current = onComplete

  // Memoized animate function to avoid re-renders triggering restarts
  const animate = useCallback(() => {
    let idx = 0

    function showNext() {
      if (idx >= lines.length) {
        // Small pause after the last line before showing results
        setTimeout(() => onCompleteRef.current(), 600)
        return
      }

      idx++
      setVisibleCount(idx)

      const currentLine = lines[idx - 1]
      const delay = currentLine?.delay ?? 200
      setTimeout(showNext, delay)
    }

    showNext()
  }, [lines])

  useEffect(() => {
    setVisibleCount(0)
    animate()
  }, [animate])

  // Auto-scroll to bottom as new lines appear
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight
    }
  }, [visibleCount])

  return (
    <div
      ref={containerRef}
      className="relative overflow-y-auto rounded-lg border border-border bg-background p-5 font-mono text-sm leading-6"
      style={{ maxHeight: "420px" }}
      role="log"
      aria-label="Terminal output"
    >
      {/* Decorative title bar */}
      <div className="mb-4 flex items-center gap-2">
        <span className="h-3 w-3 rounded-full bg-destructive/60" />
        <span className="h-3 w-3 rounded-full bg-warning/60" />
        <span className="h-3 w-3 rounded-full bg-primary/60" />
        <span className="ml-2 text-xs text-muted-foreground">rico-terminal</span>
      </div>

      {/* Rendered lines */}
      {lines.slice(0, visibleCount).map((line, i) => {
        if (line.text === "") {
          return <div key={i} className="h-3" />
        }

        const color = lineColors[line.type ?? "info"]

        return (
          <div key={i} className={`whitespace-pre-wrap break-all ${color}`}>
            {line.text}
          </div>
        )
      })}

      {/* Blinking cursor */}
      {visibleCount < lines.length && (
        <span className="inline-block h-4 w-2 animate-pulse bg-primary" />
      )}
    </div>
  )
}
