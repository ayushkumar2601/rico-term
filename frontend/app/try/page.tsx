import type { Metadata } from "next"
import { ScannerClient } from "@/components/scanner-client"

export const metadata: Metadata = {
  title: "Try Online",
  description: "Try Rico's AI-driven API security scanning directly in your browser with a demo simulation.",
}

export default function TryPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-16 lg:px-8 lg:py-24">
      <div className="mb-10">
        <h1 className="text-balance text-3xl font-bold tracking-tight text-foreground md:text-4xl">
          Try Online
        </h1>
        <p className="mt-3 max-w-2xl text-pretty leading-relaxed text-muted-foreground">
          Enter a target URL and select an action below to simulate Rico&apos;s
          AI-driven API security scanner. This demo uses simulated data to
          showcase how Rico works.
        </p>
      </div>
      <ScannerClient />
    </div>
  )
}
