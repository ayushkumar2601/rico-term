"use client"

import { useState, useCallback } from "react"
import { URLInputForm } from "@/components/url-input-form"
import { TerminalOutput } from "@/components/terminal-output"
import { ResultDisplay } from "@/components/report-display"
import { runDemoAction, type DemoResult } from "@/lib/demo-api"
import { getTerminalMessages, type TerminalLine } from "@/lib/terminal-messages"
import { Terminal } from "lucide-react"

/**
 * ScannerClient orchestrates the full Try Online workflow:
 * 1. User submits a URL + action via URLInputForm
 * 2. TerminalOutput shows an animated, line-by-line simulation of
 *    Rico's AI workflow (dummy messages for now)
 * 3. Once the animation finishes, the final report / results render
 *    below the terminal via ResultDisplay
 *
 * BACKEND INTEGRATION:
 * - Replace `runDemoAction()` with a real API call to stream results.
 * - Replace `getTerminalMessages()` with SSE / WebSocket events from
 *   the Rico backend for live terminal output.
 * - The TerminalOutput component already supports receiving lines
 *   dynamically; just push new lines into state as they arrive.
 */

type Phase = "idle" | "animating" | "done"

export function ScannerClient() {
  const [phase, setPhase] = useState<Phase>("idle")
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([])
  const [result, setResult] = useState<DemoResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [currentAction, setCurrentAction] = useState<string>("")

  /**
   * Kicks off the workflow: starts the terminal animation and fetches
   * the demo result in parallel. The result is held until the animation
   * completes so the user sees the full terminal experience first.
   */
  async function handleSubmit(url: string, action: "scan" | "attack" | "report" | "call") {
    setPhase("animating")
    setError(null)
    setResult(null)
    setCurrentAction(action)

    // Generate the terminal line sequence for the selected action
    const lines = getTerminalMessages(action, url)
    setTerminalLines(lines)

    // Fetch the demo result in the background while animation plays
    try {
      /**
       * BACKEND INTEGRATION POINT:
       * Replace `runDemoAction(url, action)` with a real fetch call:
       *
       * const response = await fetch("/api/rico", {
       *   method: "POST",
       *   headers: { "Content-Type": "application/json" },
       *   body: JSON.stringify({ url, action }),
       * })
       * const data = await response.json()
       * pendingResultRef = data
       */
      const data = await runDemoAction(url, action)
      // Store the result; it will be shown once the animation ends
      setResult(data)
    } catch {
      setError("Something went wrong. Please try again.")
      setPhase("idle")
    }
  }

  /**
   * Called by TerminalOutput when all lines have been rendered.
   * Transitions to the "done" phase so the report is revealed.
   */
  const handleAnimationComplete = useCallback(() => {
    setPhase("done")
  }, [])

  const isAnimating = phase === "animating"

  return (
    <div className="space-y-8">
      {/* Form */}
      <div className="rounded-lg border border-border bg-card p-6">
        <URLInputForm onSubmit={handleSubmit} isLoading={isAnimating} />
      </div>

      {/* Terminal animation — visible during animating and done phases */}
      {(phase === "animating" || phase === "done") && terminalLines.length > 0 && (
        <TerminalOutput
          lines={terminalLines}
          onComplete={handleAnimationComplete}
        />
      )}

      {/* Error */}
      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </div>
      )}

      {/* Results — shown after the terminal animation finishes */}
      {phase === "done" && result && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Terminal className="h-5 w-5 text-primary" />
            <h2 className="text-lg font-semibold text-foreground">
              {currentAction.charAt(0).toUpperCase() + currentAction.slice(1)} Results
            </h2>
          </div>
          <ResultDisplay result={result} />
        </div>
      )}

      {/* Empty state */}
      {phase === "idle" && !error && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-16 text-center">
          <Terminal className="h-10 w-10 text-muted-foreground/50" />
          <div>
            <p className="text-sm font-medium text-muted-foreground">
              No results yet
            </p>
            <p className="mt-1 text-xs text-muted-foreground/70">
              Enter a target URL and select an action to begin the AI-driven
              security analysis
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
