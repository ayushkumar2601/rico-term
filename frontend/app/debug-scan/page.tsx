"use client"

import { useState, useEffect, useRef } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

export default function DebugScanPage() {
  const [scanId, setScanId] = useState<string | null>(null)
  const [logs, setLogs] = useState<any[]>([])
  const [status, setStatus] = useState<string>("")
  const intervalRef = useRef<NodeJS.Timeout | null>(null)

  const startDemoScan = async () => {
    console.log("Starting demo scan...")
    try {
      const response = await fetch("http://localhost:10000/demo-scan", {
        method: "POST"
      })
      const data = await response.json()
      console.log("Demo scan response:", data)
      setScanId(data.scan_id)
      setStatus("started")
    } catch (error) {
      console.error("Error starting demo scan:", error)
      setStatus(`Error: ${error}`)
    }
  }

  useEffect(() => {
    if (!scanId) return

    console.log("Starting to poll logs for scan:", scanId)

    const pollLogs = async () => {
      try {
        const response = await fetch(`http://localhost:10000/scan/${scanId}/logs`)
        const data = await response.json()
        console.log("Logs received:", data)
        setLogs(data.logs)
      } catch (error) {
        console.error("Error fetching logs:", error)
      }
    }

    // Poll immediately
    pollLogs()

    // Then poll every 1 second
    intervalRef.current = setInterval(pollLogs, 1000)

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
      }
    }
  }, [scanId])

  return (
    <div className="container mx-auto p-8 space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Debug Scan Page</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button onClick={startDemoScan}>
            Start Demo Scan
          </Button>

          {scanId && (
            <div>
              <p>Scan ID: {scanId}</p>
              <p>Status: {status}</p>
              <p>Logs count: {logs.length}</p>
            </div>
          )}
        </CardContent>
      </Card>

      {logs.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="font-mono text-sm">Terminal Logs</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="bg-black p-4 rounded font-mono text-sm space-y-1 max-h-96 overflow-y-auto">
              {logs.map((log, index) => {
                const colorClass = 
                  log.type === "success" ? "text-green-400" :
                  log.type === "error" ? "text-red-400" :
                  log.type === "warning" ? "text-yellow-400" :
                  log.type === "dim" ? "text-gray-500" :
                  "text-gray-300";
                
                return (
                  <div key={index} className={colorClass}>
                    {log.message}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
