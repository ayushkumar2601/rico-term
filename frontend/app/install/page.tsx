import type { Metadata } from "next"
import Link from "next/link"
import { CheckCircle2 } from "lucide-react"
import { Button } from "@/components/ui/button"

export const metadata: Metadata = {
  title: "Install Locally",
  description: "Step-by-step guide to install and set up Rico on your local machine.",
}

const prerequisites = [
  "Python 3.9 or higher",
  "pip package manager",
  "Git (to clone the repository)",
  "An OpenAI API key (for AI-powered analysis)",
]

const steps = [
  {
    title: "Clone the Repository",
    description: "Download the Rico source code from GitHub.",
    code: `git clone https://github.com/your-org/rico.git
cd rico`,
  },
  {
    title: "Create a Virtual Environment",
    description: "Isolate Rico's dependencies from your system Python.",
    code: `python -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate`,
  },
  {
    title: "Install Dependencies",
    description: "Install all required Python packages.",
    code: `pip install -r requirements.txt`,
  },
  {
    title: "Configure Environment Variables",
    description: "Set up your API key and configuration. Create a .env file in the project root.",
    code: `# .env
OPENAI_API_KEY=your-openai-api-key-here
RICO_LOG_LEVEL=info
RICO_MAX_DEPTH=3
RICO_TIMEOUT=30`,
  },
  {
    title: "Verify the Installation",
    description: "Run Rico with the help command to verify everything is working.",
    code: `python -m rico --help

# Expected output:
# Usage: rico [OPTIONS] COMMAND [ARGS]...
#
# Rico - AI-Driven API Security Scanner
#
# Commands:
#   scan    Discover and classify API endpoints
#   attack  Run AI-planned security tests
#   report  Generate security reports
#   call    Make targeted API requests`,
  },
  {
    title: "Run Your First Scan",
    description: "Test Rico against a sample API to make sure it works end-to-end.",
    code: `python -m rico scan https://jsonplaceholder.typicode.com

# Rico will discover endpoints, classify them,
# and output a structured JSON report.`,
  },
]

export default function InstallPage() {
  return (
    <div className="mx-auto max-w-4xl px-4 py-16 lg:px-8 lg:py-24">
      {/* Page header */}
      <div className="mb-12">
        <h1 className="text-balance text-3xl font-bold tracking-tight text-foreground md:text-4xl">
          Install Locally
        </h1>
        <p className="mt-3 max-w-2xl text-pretty leading-relaxed text-muted-foreground">
          Get Rico running on your local machine in minutes. Follow the steps
          below to set up your own instance for full-featured API security
          scanning.
        </p>
      </div>

      {/* Prerequisites */}
      <section className="mb-12">
        <h2 className="mb-4 text-xl font-semibold text-foreground">
          Prerequisites
        </h2>
        <div className="rounded-lg border border-border bg-card p-6">
          <ul className="space-y-3">
            {prerequisites.map((req) => (
              <li key={req} className="flex items-center gap-3 text-sm">
                <CheckCircle2 className="h-4 w-4 shrink-0 text-primary" />
                <span className="text-card-foreground">{req}</span>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* Steps */}
      <section className="mb-16">
        <h2 className="mb-6 text-xl font-semibold text-foreground">
          Installation Steps
        </h2>
        <div className="space-y-8">
          {steps.map((step, index) => (
            <div key={step.title} className="relative flex gap-6">
              {/* Step number line */}
              <div className="flex flex-col items-center">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-bold text-primary-foreground">
                  {index + 1}
                </div>
                {index < steps.length - 1 && (
                  <div className="mt-2 w-px flex-1 bg-border" />
                )}
              </div>

              {/* Content */}
              <div className="flex-1 pb-2">
                <h3 className="mb-1 text-lg font-semibold text-foreground">
                  {step.title}
                </h3>
                <p className="mb-3 text-sm leading-relaxed text-muted-foreground">
                  {step.description}
                </p>
                <pre className="overflow-x-auto rounded-md border border-border bg-background p-4 font-mono text-xs leading-relaxed text-muted-foreground">
                  {step.code}
                </pre>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Troubleshooting */}
      <section className="mb-16">
        <h2 className="mb-4 text-xl font-semibold text-foreground">
          Troubleshooting
        </h2>
        <div className="space-y-4">
          {[
            {
              q: "ModuleNotFoundError when running Rico",
              a: "Make sure your virtual environment is activated and all dependencies are installed with pip install -r requirements.txt.",
            },
            {
              q: "OpenAI API key errors",
              a: "Double-check your .env file has the correct OPENAI_API_KEY value. Ensure the key is valid and has sufficient credits.",
            },
            {
              q: "Connection timeouts during scans",
              a: "Increase the RICO_TIMEOUT value in your .env file. The default is 30 seconds per request.",
            },
          ].map((item) => (
            <div
              key={item.q}
              className="rounded-lg border border-border bg-card p-5"
            >
              <h3 className="mb-1 text-sm font-semibold text-foreground">
                {item.q}
              </h3>
              <p className="text-sm leading-relaxed text-muted-foreground">
                {item.a}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Next steps CTA */}
      <div className="rounded-lg border border-primary/20 bg-secondary/50 p-8 text-center">
        <h2 className="mb-2 text-xl font-bold text-foreground">
          Installation Complete?
        </h2>
        <p className="mb-6 text-sm text-muted-foreground">
          Head to the documentation to learn all about Rico&apos;s actions, or
          try the online scanner if you want to skip local setup.
        </p>
        <div className="flex flex-wrap items-center justify-center gap-3">
          <Link href="/docs">
            <Button className="cursor-pointer">Read the Docs</Button>
          </Link>
          <Link href="/try">
            <Button variant="outline" className="cursor-pointer">
              Try Online
            </Button>
          </Link>
        </div>
      </div>
    </div>
  )
}
