"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

export default function TestApiPage() {
  const [result, setResult] = useState<string>("")
  const [loading, setLoading] = useState(false)

  const testHealth = async () => {
    setLoading(true)
    try {
      const response = await fetch("http://localhost:10000/health")
      const data = await response.json()
      setResult(JSON.stringify(data, null, 2))
    } catch (error) {
      setResult(`Error: ${error}`)
    }
    setLoading(false)
  }

  const testDemoScan = async () => {
    setLoading(true)
    try {
      const response = await fetch("http://localhost:10000/demo-scan", {
        method: "POST"
      })
      const data = await response.json()
      setResult(JSON.stringify(data, null, 2))
    } catch (error) {
      setResult(`Error: ${error}`)
    }
    setLoading(false)
  }

  return (
    <div className="container mx-auto p-8">
      <Card>
        <CardHeader>
          <CardTitle>API Test Page</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Button onClick={testHealth} disabled={loading}>
              Test Health Endpoint
            </Button>
            <Button onClick={testDemoScan} disabled={loading}>
              Test Demo Scan
            </Button>
          </div>
          
          {result && (
            <pre className="bg-black text-green-400 p-4 rounded overflow-auto">
              {result}
            </pre>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
