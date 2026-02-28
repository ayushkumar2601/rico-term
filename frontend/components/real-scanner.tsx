"use client"

import { useState, useCallback, useRef, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Progress } from "@/components/ui/progress"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { 
  Upload, 
  Loader2, 
  CheckCircle2, 
  XCircle, 
  AlertCircle,
  Shield,
  FileText,
  Clock,
  TrendingUp,
  Zap
} from "lucide-react"
import { startScan, getScanStatus, runDemoScan, getScanLogs, type ScanStatusResponse, type ScanResult, APIError } from "@/lib/api"
import { AnimatedTerminal } from "@/components/animated-terminal"

type ScanPhase = "idle" | "uploading" | "queued" | "running" | "completed" | "failed"

interface ScanLog {
  timestamp: string;
  message: string;
  type: string;
}

export function RealScanner() {
  const [phase, setPhase] = useState<ScanPhase>("idle")
  const [file, setFile] = useState<File | null>(null)
  const [baseUrl, setBaseUrl] = useState("")
  const [scanId, setScanId] = useState<string | null>(null)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [statusMessage, setStatusMessage] = useState<string>("")
  const [logs, setLogs] = useState<ScanLog[]>([])
  
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null)
  const logsPollingIntervalRef = useRef<NodeJS.Timeout | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  /**
   * Cleanup polling intervals on unmount
   */
  useEffect(() => {
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current)
      }
      if (logsPollingIntervalRef.current) {
        clearInterval(logsPollingIntervalRef.current)
      }
    }
  }, [])

  /**
   * Poll scan logs
   */
  const pollScanLogs = useCallback(async (id: string) => {
    try {
      const logsData = await getScanLogs(id)
      console.log(`📝 Logs fetched: ${logsData.logs.length} messages`)
      setLogs(logsData.logs)
    } catch (err) {
      console.error("Error polling scan logs:", err)
    }
  }, [])

  /**
   * Handle file selection
   */
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0]
    if (selectedFile) {
      // Validate file type
      const validExtensions = [".yaml", ".yml", ".json"]
      const fileExtension = selectedFile.name.toLowerCase().slice(selectedFile.name.lastIndexOf("."))
      
      if (!validExtensions.includes(fileExtension)) {
        setError("Please upload a valid OpenAPI specification file (.yaml, .yml, or .json)")
        setFile(null)
        return
      }
      
      setFile(selectedFile)
      setError(null)
    }
  }

  /**
   * Poll scan status
   */
  const pollScanStatus = useCallback(async (id: string) => {
    try {
      const status: ScanStatusResponse = await getScanStatus(id)
      
      // Update phase based on status
      if (status.status === "queued") {
        setPhase("queued")
        setStatusMessage("Scan queued, waiting to start...")
      } else if (status.status === "running") {
        setPhase("running")
        setStatusMessage("Scan in progress, analyzing endpoints...")
      } else if (status.status === "completed") {
        setPhase("completed")
        setStatusMessage("Scan completed successfully!")
        setResult(status.result || null)
        
        // Stop polling
        if (pollingIntervalRef.current) {
          clearInterval(pollingIntervalRef.current)
          pollingIntervalRef.current = null
        }
      } else if (status.status === "failed") {
        setPhase("failed")
        setError(status.error || "Scan failed with unknown error")
        
        // Stop polling
        if (pollingIntervalRef.current) {
          clearInterval(pollingIntervalRef.current)
          pollingIntervalRef.current = null
        }
      }
    } catch (err) {
      console.error("Error polling scan status:", err)
      
      // Don't fail immediately on polling errors, backend might be processing
      // Only fail after multiple consecutive errors
    }
  }, [])

  /**
   * Start polling
   */
  const startPolling = useCallback((id: string) => {
    // Clear any existing intervals
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current)
    }
    if (logsPollingIntervalRef.current) {
      clearInterval(logsPollingIntervalRef.current)
    }
    
    // Poll status immediately
    pollScanStatus(id)
    
    // Poll logs immediately
    pollScanLogs(id)
    
    // Then poll status every 3 seconds
    pollingIntervalRef.current = setInterval(() => {
      pollScanStatus(id)
    }, 3000)
    
    // Poll logs every 1 second for real-time updates
    logsPollingIntervalRef.current = setInterval(() => {
      pollScanLogs(id)
    }, 1000)
  }, [pollScanStatus, pollScanLogs])

  /**
   * Handle demo scan
   */
  const handleDemoScan = async () => {
    console.log("🚀 Demo scan button clicked!")
    
    // Reset state
    setError(null)
    setResult(null)
    setScanId(null)
    setLogs([])
    setPhase("uploading")
    setStatusMessage("Starting demo scan...")
    
    try {
      console.log("📡 Calling runDemoScan()...")
      // Start demo scan
      const response = await runDemoScan()
      console.log("✅ Demo scan response:", response)
      
      setScanId(response.scan_id)
      setPhase("queued")
      setStatusMessage(response.message || "Demo scan initiated successfully")
      
      // Start polling for status
      console.log("🔄 Starting polling for scan:", response.scan_id)
      startPolling(response.scan_id)
      
    } catch (err) {
      console.error("❌ Error starting demo scan:", err)
      
      if (err instanceof APIError) {
        setError(err.message)
      } else {
        setError("Failed to start demo scan. Please try again.")
      }
      
      setPhase("failed")
    }
  }

  /**
   * Handle form submission
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!file) {
      setError("Please select an OpenAPI specification file")
      return
    }
    
    if (!baseUrl) {
      setError("Please enter a base URL")
      return
    }
    
    // Validate URL format
    try {
      new URL(baseUrl)
    } catch {
      setError("Please enter a valid URL (e.g., https://api.example.com)")
      return
    }
    
    // Reset state
    setError(null)
    setResult(null)
    setScanId(null)
    setPhase("uploading")
    setStatusMessage("Uploading specification and starting scan...")
    
    try {
      // Start scan
      const response = await startScan({
        spec_file: file,
        base_url: baseUrl,
        use_ai: false, // Can be made configurable
        use_agentic_ai: false
      })
      
      setScanId(response.scan_id)
      setPhase("queued")
      setStatusMessage(response.message || "Scan initiated successfully")
      
      // Start polling for status
      startPolling(response.scan_id)
      
    } catch (err) {
      console.error("Error starting scan:", err)
      
      if (err instanceof APIError) {
        setError(err.message)
      } else {
        setError("Failed to start scan. Please try again.")
      }
      
      setPhase("failed")
    }
  }

  /**
   * Reset form
   */
  const handleReset = () => {
    // Clear polling
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current)
      pollingIntervalRef.current = null
    }
    if (logsPollingIntervalRef.current) {
      clearInterval(logsPollingIntervalRef.current)
      logsPollingIntervalRef.current = null
    }
    
    // Reset state
    setPhase("idle")
    setFile(null)
    setBaseUrl("")
    setScanId(null)
    setResult(null)
    setError(null)
    setStatusMessage("")
    setLogs([])
    
    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = ""
    }
  }

  const isLoading = phase === "uploading" || phase === "queued" || phase === "running"
  const isCompleted = phase === "completed"
  const isFailed = phase === "failed"

  return (
    <div className="space-y-6">
      {/* Demo Scan Button - Prominent placement */}
      {phase === "idle" && (
        <Card className="border-primary/50 bg-primary/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="h-5 w-5 text-primary" />
              Quick Demo Scan
            </CardTitle>
            <CardDescription>
              Try RICO instantly with our pre-configured demo API. No file upload required!
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button
              onClick={handleDemoScan}
              size="lg"
              className="w-full"
            >
              <Zap className="mr-2 h-5 w-5" />
              Run Demo Scan
            </Button>
            <p className="mt-3 text-center text-xs text-muted-foreground">
              This will scan a demo vulnerable API to showcase RICO's capabilities
            </p>
          </CardContent>
        </Card>
      )}

      {/* Divider */}
      {phase === "idle" && (
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <span className="w-full border-t" />
          </div>
          <div className="relative flex justify-center text-xs uppercase">
            <span className="bg-background px-2 text-muted-foreground">
              Or upload your own API spec
            </span>
          </div>
        </div>
      )}

      {/* Upload Form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            Custom API Security Scan
          </CardTitle>
          <CardDescription>
            Upload your OpenAPI specification and enter your API base URL to start a security scan
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* File Upload */}
            <div className="space-y-2">
              <Label htmlFor="spec-file">OpenAPI Specification</Label>
              <div className="flex items-center gap-2">
                <Input
                  id="spec-file"
                  ref={fileInputRef}
                  type="file"
                  accept=".yaml,.yml,.json"
                  onChange={handleFileChange}
                  disabled={isLoading}
                  className="cursor-pointer"
                />
                {file && (
                  <Badge variant="secondary" className="shrink-0">
                    {file.name}
                  </Badge>
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                Supported formats: YAML (.yaml, .yml) or JSON (.json)
              </p>
            </div>

            {/* Base URL */}
            <div className="space-y-2">
              <Label htmlFor="base-url">API Base URL</Label>
              <Input
                id="base-url"
                type="url"
                placeholder="https://api.example.com"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                disabled={isLoading}
              />
              <p className="text-xs text-muted-foreground">
                The base URL of your API to test (e.g., https://api.example.com)
              </p>
            </div>

            {/* Actions */}
            <div className="flex gap-2">
              <Button
                type="submit"
                disabled={isLoading || !file || !baseUrl}
                className="flex-1"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    {phase === "uploading" ? "Uploading..." : "Scanning..."}
                  </>
                ) : (
                  <>
                    <Upload className="mr-2 h-4 w-4" />
                    Start Scan
                  </>
                )}
              </Button>
              
              {(isCompleted || isFailed) && (
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleReset}
                >
                  New Scan
                </Button>
              )}
            </div>
          </form>
        </CardContent>
      </Card>

      {/* Status Display */}
      {(isLoading || isCompleted || isFailed) && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {isLoading && <Loader2 className="h-5 w-5 animate-spin text-primary" />}
              {isCompleted && <CheckCircle2 className="h-5 w-5 text-green-500" />}
              {isFailed && <XCircle className="h-5 w-5 text-destructive" />}
              Scan Status
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Scan ID */}
            {scanId && (
              <div className="flex items-center justify-between rounded-lg border border-border bg-muted/50 p-3">
                <span className="text-sm font-medium">Scan ID:</span>
                <code className="text-xs text-muted-foreground">{scanId}</code>
              </div>
            )}

            {/* Status Message */}
            {statusMessage && (
              <Alert>
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>{statusMessage}</AlertDescription>
              </Alert>
            )}

            {/* Progress Bar */}
            {isLoading && (
              <div className="space-y-2">
                <Progress value={undefined} className="h-2" />
                <p className="text-center text-xs text-muted-foreground">
                  {phase === "uploading" && "Uploading specification..."}
                  {phase === "queued" && "Waiting in queue..."}
                  {phase === "running" && "Analyzing endpoints and testing vulnerabilities..."}
                </p>
              </div>
            )}

            {/* Error Display */}
            {error && (
              <Alert variant="destructive">
                <XCircle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
      )}

      {/* Real-Time Terminal Logs with Animation */}
      {scanId && logs.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 font-mono text-sm">
              <span className="flex gap-1">
                <span className="h-3 w-3 rounded-full bg-red-500" />
                <span className="h-3 w-3 rounded-full bg-yellow-500" />
                <span className="h-3 w-3 rounded-full bg-green-500" />
              </span>
              rico-terminal
            </CardTitle>
            <CardDescription>Real-time scan execution logs</CardDescription>
          </CardHeader>
          <CardContent>
            <AnimatedTerminal logs={logs} isLoading={isLoading} />
          </CardContent>
        </Card>
      )}

      {/* Results Display */}
      {isCompleted && result && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5 text-primary" />
              Scan Results
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="summary" className="w-full">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="summary">Summary</TabsTrigger>
                <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
                <TabsTrigger value="raw">Raw Data</TabsTrigger>
              </TabsList>

              {/* Summary Tab */}
              <TabsContent value="summary" className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium text-muted-foreground">
                        Risk Score
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex items-center gap-2">
                        <TrendingUp className="h-4 w-4 text-destructive" />
                        <span className="text-2xl font-bold">{result.risk_score}</span>
                        <Badge variant={
                          result.risk_level === "Critical" ? "destructive" :
                          result.risk_level === "High" ? "destructive" :
                          result.risk_level === "Medium" ? "default" : "secondary"
                        }>
                          {result.risk_level}
                        </Badge>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium text-muted-foreground">
                        Vulnerabilities
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">{result.total_vulnerabilities}</div>
                      <p className="text-xs text-muted-foreground">issues found</p>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium text-muted-foreground">
                        Endpoints Tested
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">
                        {result.endpoints_tested}/{result.total_endpoints}
                      </div>
                      <p className="text-xs text-muted-foreground">endpoints scanned</p>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium text-muted-foreground">
                        <Clock className="inline h-4 w-4" /> Duration
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">{result.duration.toFixed(1)}s</div>
                      <p className="text-xs text-muted-foreground">scan time</p>
                    </CardContent>
                  </Card>
                </div>

                {/* Severity Distribution */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">Severity Distribution</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {Object.entries(result.severity_distribution).map(([severity, count]) => (
                        count > 0 && (
                          <div key={severity} className="flex items-center justify-between">
                            <Badge variant={
                              severity === "Critical" ? "destructive" :
                              severity === "High" ? "destructive" :
                              severity === "Medium" ? "default" : "secondary"
                            }>
                              {severity}
                            </Badge>
                            <span className="text-sm font-medium">{count}</span>
                          </div>
                        )
                      ))}
                    </div>
                  </CardContent>
                </Card>

                {/* Top Issue */}
                {result.top_issue && (
                  <Alert>
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Top Issue:</strong> {result.top_issue}
                    </AlertDescription>
                  </Alert>
                )}
              </TabsContent>

              {/* Vulnerabilities Tab */}
              <TabsContent value="vulnerabilities" className="space-y-4">
                {result.vulnerabilities.length === 0 ? (
                  <Alert>
                    <CheckCircle2 className="h-4 w-4" />
                    <AlertDescription>
                      No vulnerabilities detected. Your API appears secure!
                    </AlertDescription>
                  </Alert>
                ) : (
                  <div className="space-y-3">
                    {result.vulnerabilities.map((vuln, index) => (
                      <Card key={index}>
                        <CardHeader className="pb-3">
                          <div className="flex items-start justify-between">
                            <div className="space-y-1">
                              <CardTitle className="text-base">{vuln.type}</CardTitle>
                              <CardDescription className="text-xs">
                                {vuln.method} {vuln.endpoint}
                              </CardDescription>
                            </div>
                            <Badge variant={
                              vuln.severity === "Critical" ? "destructive" :
                              vuln.severity === "High" ? "destructive" :
                              vuln.severity === "Medium" ? "default" : "secondary"
                            }>
                              {vuln.severity}
                            </Badge>
                          </div>
                        </CardHeader>
                        <CardContent className="space-y-2">
                          <p className="text-sm text-muted-foreground">{vuln.description}</p>
                          <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <span>Confidence: {vuln.confidence}%</span>
                            <span>CVSS: {vuln.cvss_score}</span>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </TabsContent>

              {/* Raw Data Tab */}
              <TabsContent value="raw">
                <Card>
                  <CardContent className="pt-6">
                    <pre className="overflow-auto rounded-lg bg-muted p-4 text-xs">
                      {JSON.stringify(result, null, 2)}
                    </pre>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
