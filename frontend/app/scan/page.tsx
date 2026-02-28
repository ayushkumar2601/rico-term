import type { Metadata } from "next"
import { RealScanner } from "@/components/real-scanner"

export const metadata: Metadata = {
  title: "API Security Scan",
  description: "Upload your OpenAPI specification and scan your API for security vulnerabilities using RICO's AI-powered scanner.",
}

export default function ScanPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-16 lg:px-8 lg:py-24">
      <div className="mb-10">
        <h1 className="text-balance text-3xl font-bold tracking-tight text-foreground md:text-4xl">
          API Security Scan
        </h1>
        <p className="mt-3 max-w-2xl text-pretty leading-relaxed text-muted-foreground">
          Upload your OpenAPI specification file and enter your API base URL to perform a comprehensive security scan.
          RICO will analyze your endpoints and test for common vulnerabilities including IDOR, SQL Injection, and authentication issues.
        </p>
      </div>
      <RealScanner />
    </div>
  )
}
