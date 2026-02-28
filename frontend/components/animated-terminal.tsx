"use client"

import { useEffect, useRef, useState } from "react"

interface TerminalLog {
  timestamp: string
  message: string
  type: string
}

interface AnimatedTerminalProps {
  logs: TerminalLog[]
  isLoading: boolean
}

export function AnimatedTerminal({ logs, isLoading }: AnimatedTerminalProps) {
  const [displayedLogs, setDisplayedLogs] = useState<Array<{ message: string; type: string; isComplete: boolean }>>([])
  const [currentLogIndex, setCurrentLogIndex] = useState(0)
  const [currentCharIndex, setCurrentCharIndex] = useState(0)
  const terminalRef = useRef<HTMLDivElement>(null)

  // Auto-scroll to bottom
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [displayedLogs, currentCharIndex])

  // Animation effect
  useEffect(() => {
    if (currentLogIndex >= logs.length) return

    const currentLog = logs[currentLogIndex]
    const targetMessage = currentLog.message

    // If this is a new log, add it to displayed logs
    if (displayedLogs.length <= currentLogIndex) {
      setDisplayedLogs(prev => [...prev, { message: "", type: currentLog.type, isComplete: false }])
    }

    // Empty messages appear instantly
    if (targetMessage === "") {
      setDisplayedLogs(prev => {
        const newLogs = [...prev]
        newLogs[currentLogIndex] = { message: "", type: currentLog.type, isComplete: true }
        return newLogs
      })
      setCurrentLogIndex(prev => prev + 1)
      setCurrentCharIndex(0)
      return
    }

    // Typing animation
    if (currentCharIndex < targetMessage.length) {
      const timer = setTimeout(() => {
        setDisplayedLogs(prev => {
          const newLogs = [...prev]
          newLogs[currentLogIndex] = {
            message: targetMessage.slice(0, currentCharIndex + 1),
            type: currentLog.type,
            isComplete: false
          }
          return newLogs
        })
        setCurrentCharIndex(prev => prev + 1)
      }, 10) // 10ms per character for smooth typing

      return () => clearTimeout(timer)
    } else {
      // Mark current log as complete and move to next
      setDisplayedLogs(prev => {
        const newLogs = [...prev]
        newLogs[currentLogIndex] = {
          message: targetMessage,
          type: currentLog.type,
          isComplete: true
        }
        return newLogs
      })
      
      // Small delay before next log
      const timer = setTimeout(() => {
        setCurrentLogIndex(prev => prev + 1)
        setCurrentCharIndex(0)
      }, 50)

      return () => clearTimeout(timer)
    }
  }, [logs, currentLogIndex, currentCharIndex, displayedLogs.length])

  // Reset animation when logs change significantly (new scan)
  useEffect(() => {
    if (logs.length === 0) {
      setDisplayedLogs([])
      setCurrentLogIndex(0)
      setCurrentCharIndex(0)
    }
  }, [logs.length])

  return (
    <div 
      ref={terminalRef}
      className="relative overflow-y-auto rounded-lg border border-border bg-black p-4 font-mono text-sm leading-6" 
      style={{ maxHeight: "400px" }}
    >
      {displayedLogs.map((log, index) => {
        const colorClass = 
          log.type === "success" ? "text-green-400" :
          log.type === "error" ? "text-red-400" :
          log.type === "warning" ? "text-yellow-400" :
          log.type === "dim" ? "text-gray-500" :
          "text-gray-300"
        
        return (
          <div key={index} className={`whitespace-pre-wrap break-all ${colorClass}`}>
            {log.message}
            {!log.isComplete && index === currentLogIndex && (
              <span className="inline-block w-2 h-4 bg-green-400 animate-pulse ml-1" />
            )}
          </div>
        )
      })}
      
      {/* Blinking cursor at the end */}
      {isLoading && currentLogIndex >= logs.length && (
        <span className="inline-block h-4 w-2 animate-pulse bg-green-400" />
      )}
    </div>
  )
}
