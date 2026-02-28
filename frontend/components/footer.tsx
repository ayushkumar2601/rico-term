import Link from "next/link"
import { Shield } from "lucide-react"

export function Footer() {
  return (
    <footer className="border-t border-border bg-background">
      <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-4 py-8 md:flex-row lg:px-8">
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          <span className="text-sm font-semibold text-foreground">Rico</span>
        </div>

        <nav className="flex gap-6 text-sm text-muted-foreground" aria-label="Footer navigation">
          <Link href="/docs" className="hover:text-foreground transition-colors">
            Docs
          </Link>
          <Link href="/install" className="hover:text-foreground transition-colors">
            Install
          </Link>
          <Link href="/try" className="hover:text-foreground transition-colors">
            Try Online
          </Link>
        </nav>

        <p className="text-xs text-muted-foreground">
          Rico &mdash; AI-Driven API Security Scanner
        </p>
      </div>
    </footer>
  )
}
