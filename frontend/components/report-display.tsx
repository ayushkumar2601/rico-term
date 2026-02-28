import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import type { DemoResult } from "@/lib/demo-api"
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  Globe,
  Clock,
  Lock,
  Unlock,
} from "lucide-react"

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    Critical: "bg-destructive/15 text-destructive border-destructive/30",
    High: "bg-destructive/10 text-destructive border-destructive/20",
    Medium: "bg-warning/15 text-warning border-warning/30",
    Low: "bg-muted text-muted-foreground border-border",
  }

  return (
    <Badge variant="outline" className={cn("font-medium", colors[severity] ?? colors.Low)}>
      {severity}
    </Badge>
  )
}

function ScanDisplay({ data }: { data: DemoResult & { type: "scan" } }) {
  const result = data.data
  return (
    <div className="space-y-6">
      {/* Summary bar */}
      <div className="flex flex-wrap items-center gap-4 rounded-lg border border-border bg-secondary/50 p-4">
        <div className="flex items-center gap-2 text-sm">
          <Globe className="h-4 w-4 text-primary" />
          <span className="text-muted-foreground">Target:</span>
          <span className="font-medium text-foreground">{result.target}</span>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <Shield className="h-4 w-4 text-primary" />
          <span className="text-muted-foreground">Endpoints:</span>
          <span className="font-medium text-foreground">{result.total_endpoints}</span>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <Clock className="h-4 w-4 text-primary" />
          <span className="text-muted-foreground">Time:</span>
          <span className="font-medium text-foreground">{result.scan_time}</span>
        </div>
      </div>

      {/* Endpoints table */}
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-secondary/50">
              <th className="px-4 py-3 text-left font-medium text-foreground">Path</th>
              <th className="px-4 py-3 text-left font-medium text-foreground">Method</th>
              <th className="px-4 py-3 text-left font-medium text-foreground">Classification</th>
              <th className="px-4 py-3 text-left font-medium text-foreground">Auth</th>
              <th className="px-4 py-3 text-left font-medium text-foreground">Parameters</th>
            </tr>
          </thead>
          <tbody>
            {result.endpoints.map((ep, i) => (
              <tr key={`${ep.path}-${ep.method}-${i}`} className="border-b border-border last:border-0">
                <td className="px-4 py-3 font-mono text-xs text-foreground">{ep.path}</td>
                <td className="px-4 py-3">
                  <Badge variant="outline" className="font-mono text-xs">
                    {ep.method}
                  </Badge>
                </td>
                <td className="px-4 py-3 text-muted-foreground">{ep.classification}</td>
                <td className="px-4 py-3">
                  {ep.auth_required ? (
                    <Lock className="h-4 w-4 text-warning" />
                  ) : (
                    <Unlock className="h-4 w-4 text-muted-foreground" />
                  )}
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {ep.parameters.map((p) => (
                      <Badge key={p} variant="secondary" className="text-xs">
                        {p}
                      </Badge>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function AttackDisplay({ data }: { data: DemoResult & { type: "attack" } }) {
  const result = data.data
  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="flex flex-wrap items-center gap-4 rounded-lg border border-border bg-secondary/50 p-4">
        <div className="flex items-center gap-2 text-sm">
          <Globe className="h-4 w-4 text-primary" />
          <span className="text-muted-foreground">Target:</span>
          <span className="font-medium text-foreground">{result.target}</span>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <AlertTriangle className="h-4 w-4 text-destructive" />
          <span className="text-muted-foreground">Findings:</span>
          <span className="font-medium text-foreground">{result.total_findings}</span>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <Clock className="h-4 w-4 text-primary" />
          <span className="text-muted-foreground">Time:</span>
          <span className="font-medium text-foreground">{result.attack_time}</span>
        </div>
      </div>

      {/* Findings cards */}
      <div className="space-y-4">
        {result.findings.map((finding, i) => (
          <div
            key={`${finding.endpoint}-${i}`}
            className="rounded-lg border border-border bg-card p-5"
          >
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <code className="rounded bg-secondary px-2 py-0.5 font-mono text-xs text-foreground">
                  {finding.endpoint}
                </code>
              </div>
              <SeverityBadge severity={finding.severity} />
            </div>
            <h4 className="mb-1 text-sm font-semibold text-foreground">
              {finding.vulnerability}
            </h4>
            <p className="mb-3 text-sm leading-relaxed text-muted-foreground">
              {finding.description}
            </p>
            <div className="rounded-md bg-background p-3">
              <p className="text-xs font-medium text-muted-foreground">
                <span className="text-primary">Evidence:</span> {finding.evidence}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function ReportDisplay({ data }: { data: DemoResult & { type: "report" } }) {
  const result = data.data
  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="flex flex-wrap items-center gap-4 rounded-lg border border-border bg-secondary/50 p-4">
        <div className="flex items-center gap-2 text-sm">
          <Globe className="h-4 w-4 text-primary" />
          <span className="text-muted-foreground">Target:</span>
          <span className="font-medium text-foreground">{result.target}</span>
        </div>
      </div>

      {/* Severity overview */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {([
          { label: "Critical", value: result.summary.critical, color: "text-destructive" },
          { label: "High", value: result.summary.high, color: "text-destructive" },
          { label: "Medium", value: result.summary.medium, color: "text-warning" },
          { label: "Low", value: result.summary.low, color: "text-muted-foreground" },
        ] as const).map((item) => (
          <div key={item.label} className="rounded-lg border border-border bg-card p-4 text-center">
            <div className={cn("text-3xl font-bold", item.color)}>{item.value}</div>
            <div className="mt-1 text-xs text-muted-foreground">{item.label}</div>
          </div>
        ))}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4">
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-2xl font-bold text-foreground">{result.summary.total_endpoints}</div>
          <div className="text-xs text-muted-foreground">Endpoints Scanned</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <div className="text-2xl font-bold text-foreground">{result.summary.total_findings}</div>
          <div className="text-xs text-muted-foreground">Vulnerabilities Found</div>
        </div>
      </div>

      {/* Recommendations */}
      <div className="rounded-lg border border-border bg-card p-6">
        <h3 className="mb-4 text-lg font-semibold text-foreground">Recommendations</h3>
        <ul className="space-y-3">
          {result.recommendations.map((rec, i) => (
            <li key={i} className="flex items-start gap-3 text-sm">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
              <span className="leading-relaxed text-muted-foreground">{rec}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}

function CallDisplay({ data }: { data: DemoResult & { type: "call" } }) {
  const result = data.data
  return (
    <div className="space-y-6">
      {/* Status bar */}
      <div className="flex flex-wrap items-center gap-4 rounded-lg border border-border bg-secondary/50 p-4">
        <div className="flex items-center gap-2 text-sm">
          <Globe className="h-4 w-4 text-primary" />
          <span className="text-muted-foreground">URL:</span>
          <span className="font-mono text-xs text-foreground">{result.target}</span>
        </div>
        <Badge
          variant="outline"
          className={cn(
            "font-mono",
            result.status < 300 ? "border-primary/30 text-primary" : "border-destructive/30 text-destructive"
          )}
        >
          {result.status} {result.status_text}
        </Badge>
        <div className="flex items-center gap-2 text-sm">
          <Clock className="h-4 w-4 text-primary" />
          <span className="text-muted-foreground">{result.response_time}</span>
        </div>
      </div>

      {/* Headers */}
      <div className="rounded-lg border border-border bg-card p-5">
        <h3 className="mb-3 text-sm font-semibold text-foreground">Response Headers</h3>
        <div className="space-y-1.5">
          {Object.entries(result.headers).map(([key, value]) => (
            <div key={key} className="flex gap-2 font-mono text-xs">
              <span className="text-primary">{key}:</span>
              <span className="text-muted-foreground">{value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Body */}
      <div className="rounded-lg border border-border bg-card p-5">
        <h3 className="mb-3 text-sm font-semibold text-foreground">Response Body</h3>
        <pre className="overflow-x-auto rounded-md bg-background p-4 font-mono text-xs leading-relaxed text-muted-foreground">
          {JSON.stringify(result.body, null, 2)}
        </pre>
      </div>
    </div>
  )
}

interface ReportDisplayProps {
  result: DemoResult
}

export function ResultDisplay({ result }: ReportDisplayProps) {
  switch (result.type) {
    case "scan":
      return <ScanDisplay data={result} />
    case "attack":
      return <AttackDisplay data={result} />
    case "report":
      return <ReportDisplay data={result} />
    case "call":
      return <CallDisplay data={result} />
  }
}
