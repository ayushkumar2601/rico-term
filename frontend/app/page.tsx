import Link from "next/link"
import { Shield, Scan, Swords, FileText, Zap, Lock, Brain } from "lucide-react"
import { Button } from "@/components/ui/button"

const features = [
  {
    icon: Scan,
    title: "Endpoint Discovery",
    description:
      "Automatically discovers and catalogs every API endpoint in your application, mapping out the full attack surface.",
  },
  {
    icon: Brain,
    title: "AI-Powered Classification",
    description:
      "Uses advanced AI to classify endpoints, understand data flows, and identify patterns indicative of vulnerabilities.",
  },
  {
    icon: Swords,
    title: "Intelligent Attack Planning",
    description:
      "Plans targeted security tests based on each endpoint's classification, simulating real-world attack scenarios.",
  },
  {
    icon: FileText,
    title: "Detailed Reporting",
    description:
      "Generates structured, actionable security reports with severity ratings, evidence, and remediation guidance.",
  },
  {
    icon: Lock,
    title: "Auth & Injection Testing",
    description:
      "Tests for BOLA, IDOR, SQL injection, XSS, and other OWASP API Security Top 10 vulnerabilities.",
  },
  {
    icon: Zap,
    title: "Fast & Automated",
    description:
      "Run full scans in minutes, not hours. Integrate into your CI/CD pipeline for continuous API security testing.",
  },
]

const actions = [
  {
    name: "Scan",
    description: "Discover and catalog API endpoints from a target URL, creating a complete inventory of the attack surface.",
    command: "rico scan https://api.example.com",
  },
  {
    name: "Attack",
    description: "Execute AI-planned security tests against discovered endpoints to identify real vulnerabilities.",
    command: "rico attack https://api.example.com",
  },
  {
    name: "Report",
    description: "Generate a detailed security report with findings, severity levels, and remediation steps.",
    command: "rico report https://api.example.com",
  },
  {
    name: "Call",
    description: "Make targeted API calls to specific endpoints for manual testing and verification.",
    command: 'rico call https://api.example.com/users --method POST --data \'{"test":true}\'',
  },
]

export default function LandingPage() {
  return (
    <div className="flex flex-col">
      {/* Hero */}
      <section className="relative overflow-hidden py-24 lg:py-36">
        {/* Subtle grid background */}
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage:
              "linear-gradient(to right, var(--foreground) 1px, transparent 1px), linear-gradient(to bottom, var(--foreground) 1px, transparent 1px)",
            backgroundSize: "64px 64px",
          }}
        />
        <div className="relative mx-auto max-w-7xl px-4 text-center lg:px-8">
          <div className="mx-auto flex max-w-3xl flex-col items-center gap-6">
            <div className="flex items-center gap-2 rounded-full border border-border bg-secondary px-4 py-1.5 text-xs font-medium text-muted-foreground">
              <Shield className="h-3.5 w-3.5 text-primary" />
              AI-Driven API Security
            </div>
            <h1 className="text-balance text-4xl font-bold tracking-tight text-foreground md:text-6xl lg:text-7xl">
              Secure Your APIs with{" "}
              <span className="text-primary">AI-Powered</span> Intelligence
            </h1>
            <p className="max-w-2xl text-pretty text-lg leading-relaxed text-muted-foreground md:text-xl">
              Rico is an open-source, AI-driven API security scanner that
              discovers, classifies, attacks, and reports on your API endpoints
              automatically.
            </p>
            <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
              <Link href="/scan">
                <Button size="lg" className="cursor-pointer">
                  Scan Your API
                </Button>
              </Link>
              <Link href="/try">
                <Button size="lg" variant="outline" className="cursor-pointer">
                  Try Demo
                </Button>
              </Link>
              <Link href="/install">
                <Button size="lg" variant="outline" className="cursor-pointer">
                  Install Locally
                </Button>
              </Link>
              <Link href="/docs">
                <Button size="lg" variant="ghost" className="cursor-pointer text-muted-foreground hover:text-foreground">
                  Read the Docs
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section className="border-t border-border py-24 lg:py-32">
        <div className="mx-auto max-w-7xl px-4 lg:px-8">
          <div className="mx-auto mb-16 max-w-2xl text-center">
            <h2 className="text-balance text-3xl font-bold tracking-tight text-foreground md:text-4xl">
              Everything You Need for API Security
            </h2>
            <p className="mt-4 text-pretty text-muted-foreground">
              Rico combines AI intelligence with proven security testing
              methodologies to deliver comprehensive API protection.
            </p>
          </div>
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {features.map((feature) => (
              <div
                key={feature.title}
                className="group rounded-lg border border-border bg-card p-6 transition-colors hover:border-primary/30"
              >
                <feature.icon className="mb-4 h-8 w-8 text-primary transition-transform group-hover:scale-110" />
                <h3 className="mb-2 text-lg font-semibold text-card-foreground">
                  {feature.title}
                </h3>
                <p className="text-sm leading-relaxed text-muted-foreground">
                  {feature.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Actions Section */}
      <section className="border-t border-border bg-secondary/30 py-24 lg:py-32">
        <div className="mx-auto max-w-7xl px-4 lg:px-8">
          <div className="mx-auto mb-16 max-w-2xl text-center">
            <h2 className="text-balance text-3xl font-bold tracking-tight text-foreground md:text-4xl">
              Four Core Actions
            </h2>
            <p className="mt-4 text-pretty text-muted-foreground">
              Rico&apos;s workflow is built around four powerful actions that
              cover the entire API security testing lifecycle.
            </p>
          </div>
          <div className="grid gap-6 md:grid-cols-2">
            {actions.map((action) => (
              <div
                key={action.name}
                className="rounded-lg border border-border bg-card p-6"
              >
                <h3 className="mb-2 text-lg font-semibold text-primary">
                  {action.name}
                </h3>
                <p className="mb-4 text-sm leading-relaxed text-muted-foreground">
                  {action.description}
                </p>
                <div className="rounded-md bg-background p-3 font-mono text-xs text-muted-foreground">
                  <span className="text-primary">$</span> {action.command}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="border-t border-border py-24 lg:py-32">
        <div className="mx-auto max-w-3xl px-4 text-center lg:px-8">
          <h2 className="text-balance text-3xl font-bold tracking-tight text-foreground md:text-4xl">
            Ready to Secure Your APIs?
          </h2>
          <p className="mt-4 text-pretty text-muted-foreground">
            Start scanning your APIs now with our online demo or install Rico
            locally for full control.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/scan">
              <Button size="lg" className="cursor-pointer">Scan Your API Now</Button>
            </Link>
            <Link href="/try">
              <Button size="lg" variant="outline" className="cursor-pointer">
                Try Demo
              </Button>
            </Link>
            <Link href="/install">
              <Button size="lg" variant="outline" className="cursor-pointer">
                Local Installation
              </Button>
            </Link>
          </div>
        </div>
      </section>
    </div>
  )
}
