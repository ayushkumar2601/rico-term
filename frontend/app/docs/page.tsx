import type { Metadata } from "next"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"

export const metadata: Metadata = {
  title: "Documentation",
  description: "Learn how to use Rico's AI-driven API security scanning actions: Scan, Attack, Report, and Call.",
}

const scanExample = `{
  "target": "https://api.example.com",
  "endpoints": [
    {
      "path": "/api/v1/users",
      "method": "GET",
      "classification": "user-data",
      "auth_required": true,
      "parameters": ["page", "limit"]
    },
    {
      "path": "/api/v1/users/{id}",
      "method": "GET",
      "classification": "user-data",
      "auth_required": true,
      "parameters": ["id"]
    },
    {
      "path": "/api/v1/login",
      "method": "POST",
      "classification": "authentication",
      "auth_required": false,
      "parameters": ["username", "password"]
    }
  ],
  "total_endpoints": 3,
  "scan_time": "2.4s"
}`

const attackExample = `{
  "target": "https://api.example.com",
  "findings": [
    {
      "endpoint": "/api/v1/users/{id}",
      "vulnerability": "BOLA/IDOR",
      "severity": "High",
      "description": "Accessing user data with different user IDs returns data without authorization checks.",
      "evidence": "GET /api/v1/users/2 returned user data while authenticated as user 1."
    },
    {
      "endpoint": "/api/v1/login",
      "vulnerability": "Brute Force Susceptible",
      "severity": "Medium",
      "description": "No rate limiting detected on login endpoint.",
      "evidence": "100 requests in 10 seconds without being blocked."
    }
  ],
  "total_findings": 2,
  "attack_time": "12.8s"
}`

const reportExample = `{
  "target": "https://api.example.com",
  "summary": {
    "total_endpoints": 3,
    "total_findings": 2,
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 0
  },
  "recommendations": [
    "Implement object-level authorization checks on /api/v1/users/{id}.",
    "Add rate limiting to /api/v1/login to prevent brute-force attacks.",
    "Consider implementing API key or token-based rate limiting globally."
  ]
}`

const callExample = `$ rico call https://api.example.com/api/v1/users \\
    --method GET \\
    --header "Authorization: Bearer <token>"

Response (200 OK):
{
  "users": [
    { "id": 1, "name": "Alice", "email": "alice@example.com" },
    { "id": 2, "name": "Bob", "email": "bob@example.com" }
  ],
  "total": 2,
  "page": 1
}`

const actions = [
  {
    id: "scan",
    title: "Scan",
    description:
      "The Scan action crawls a target API URL and discovers all available endpoints. It analyzes response structures, HTTP methods, authentication requirements, and parameter types. The AI engine then classifies each endpoint to understand its purpose and data sensitivity.",
    usage: "rico scan <target_url> [options]",
    flags: [
      { flag: "--depth <n>", desc: "Maximum crawl depth (default: 3)" },
      { flag: "--auth <token>", desc: "Bearer token for authenticated scanning" },
      { flag: "--output <file>", desc: "Save results to a JSON file" },
    ],
    example: scanExample,
  },
  {
    id: "attack",
    title: "Attack",
    description:
      "The Attack action uses AI to plan and execute security tests against discovered endpoints. It generates targeted payloads based on each endpoint's classification, testing for OWASP API Top 10 vulnerabilities like BOLA, injection, broken authentication, and more.",
    usage: "rico attack <target_url> [options]",
    flags: [
      { flag: "--scan-file <file>", desc: "Use a previous scan result file" },
      { flag: "--severity <level>", desc: "Minimum severity to test (low, medium, high, critical)" },
      { flag: "--safe-mode", desc: "Non-destructive tests only" },
    ],
    example: attackExample,
  },
  {
    id: "report",
    title: "Report",
    description:
      "The Report action aggregates scan and attack results into a comprehensive security report. It includes severity ratings, evidence, and actionable remediation guidance for each finding.",
    usage: "rico report <target_url> [options]",
    flags: [
      { flag: "--format <type>", desc: "Output format: json, html, pdf (default: json)" },
      { flag: "--include-evidence", desc: "Include raw request/response evidence" },
      { flag: "--output <file>", desc: "Save the report to a file" },
    ],
    example: reportExample,
  },
  {
    id: "call",
    title: "Call",
    description:
      "The Call action lets you make targeted API requests to specific endpoints for manual testing and verification. It supports custom headers, methods, and request bodies.",
    usage: "rico call <endpoint_url> [options]",
    flags: [
      { flag: "--method <verb>", desc: "HTTP method (GET, POST, PUT, DELETE, etc.)" },
      { flag: "--header <key:value>", desc: "Custom request header (repeatable)" },
      { flag: "--data <json>", desc: "Request body as JSON" },
    ],
    example: callExample,
  },
]

export default function DocsPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-16 lg:px-8 lg:py-24">
      {/* Page header */}
      <div className="mb-12">
        <h1 className="text-balance text-3xl font-bold tracking-tight text-foreground md:text-4xl">
          Documentation
        </h1>
        <p className="mt-3 max-w-2xl text-pretty leading-relaxed text-muted-foreground">
          Learn how to use Rico&apos;s four core actions to scan, test, and
          secure your API endpoints. Each action is designed to work
          independently or as part of a complete security testing pipeline.
        </p>
      </div>

      {/* Quick overview */}
      <section className="mb-16">
        <h2 className="mb-4 text-xl font-semibold text-foreground">
          Quick Overview
        </h2>
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-secondary/50">
                <th className="px-4 py-3 text-left font-medium text-foreground">
                  Action
                </th>
                <th className="px-4 py-3 text-left font-medium text-foreground">
                  Purpose
                </th>
                <th className="px-4 py-3 text-left font-medium text-foreground">
                  Command
                </th>
              </tr>
            </thead>
            <tbody>
              {[
                { action: "Scan", purpose: "Discover & classify endpoints", cmd: "rico scan <url>" },
                { action: "Attack", purpose: "Run AI-planned security tests", cmd: "rico attack <url>" },
                { action: "Report", purpose: "Generate security reports", cmd: "rico report <url>" },
                { action: "Call", purpose: "Make targeted API requests", cmd: "rico call <url>" },
              ].map((row) => (
                <tr key={row.action} className="border-b border-border last:border-0">
                  <td className="px-4 py-3 font-medium text-primary">{row.action}</td>
                  <td className="px-4 py-3 text-muted-foreground">{row.purpose}</td>
                  <td className="px-4 py-3">
                    <code className="rounded bg-secondary px-2 py-0.5 font-mono text-xs text-foreground">
                      {row.cmd}
                    </code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Detailed actions */}
      <section>
        <h2 className="mb-6 text-xl font-semibold text-foreground">
          Actions in Detail
        </h2>

        <Tabs defaultValue="scan" className="w-full">
          <TabsList className="mb-6 w-full justify-start overflow-x-auto">
            {actions.map((a) => (
              <TabsTrigger key={a.id} value={a.id} className="cursor-pointer">
                {a.title}
              </TabsTrigger>
            ))}
          </TabsList>

          {actions.map((action) => (
            <TabsContent key={action.id} value={action.id}>
              <div className="rounded-lg border border-border bg-card p-6 lg:p-8">
                <h3 className="mb-3 text-2xl font-bold text-foreground">
                  {action.title}
                </h3>
                <p className="mb-6 leading-relaxed text-muted-foreground">
                  {action.description}
                </p>

                {/* Usage */}
                <div className="mb-6">
                  <h4 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                    Usage
                  </h4>
                  <div className="rounded-md bg-background p-3 font-mono text-sm text-foreground">
                    <span className="text-primary">$</span> {action.usage}
                  </div>
                </div>

                {/* Flags */}
                <div className="mb-6">
                  <h4 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                    Options
                  </h4>
                  <div className="space-y-2">
                    {action.flags.map((f) => (
                      <div key={f.flag} className="flex items-start gap-3">
                        <Badge variant="secondary" className="shrink-0 font-mono text-xs">
                          {f.flag}
                        </Badge>
                        <span className="text-sm text-muted-foreground">
                          {f.desc}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Example output */}
                <div>
                  <h4 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                    Example Output
                  </h4>
                  <pre className="overflow-x-auto rounded-md bg-background p-4 font-mono text-xs leading-relaxed text-muted-foreground">
                    {action.example}
                  </pre>
                </div>
              </div>
            </TabsContent>
          ))}
        </Tabs>
      </section>
    </div>
  )
}
