"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { useState } from "react"
import { Shield, Menu, X } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"

const navLinks = [
  { href: "/", label: "Home" },
  { href: "/docs", label: "Documentation" },
  { href: "/install", label: "Install" },
  { href: "/scan", label: "Scan API" },
  { href: "/try", label: "Try Demo" },
]

export function Header() {
  const pathname = usePathname()
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 lg:px-8">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2">
          <Shield className="h-7 w-7 text-primary" />
          <span className="text-xl font-bold tracking-tight text-foreground">
            Rico
          </span>
        </Link>

        {/* Desktop nav */}
        <nav className="hidden items-center gap-1 md:flex" aria-label="Main navigation">
          {navLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={cn(
                "rounded-md px-3 py-2 text-sm font-medium transition-colors",
                pathname === link.href
                  ? "text-primary"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {link.label}
            </Link>
          ))}
        </nav>

        {/* CTA + mobile toggle */}
        <div className="flex items-center gap-3">
          <Link href="/scan" className="hidden md:block">
            <Button size="sm" className="cursor-pointer">Launch Scanner</Button>
          </Link>
          <button
            className="inline-flex items-center justify-center rounded-md p-2 text-muted-foreground hover:text-foreground md:hidden"
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label="Toggle navigation menu"
          >
            {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>
      </div>

      {/* Mobile nav */}
      {mobileOpen && (
        <nav className="border-t border-border md:hidden" aria-label="Mobile navigation">
          <div className="mx-auto max-w-7xl space-y-1 px-4 py-3">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                href={link.href}
                onClick={() => setMobileOpen(false)}
                className={cn(
                  "block rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  pathname === link.href
                    ? "bg-secondary text-primary"
                    : "text-muted-foreground hover:bg-secondary hover:text-foreground"
                )}
              >
                {link.label}
              </Link>
            ))}
            <Link href="/scan" onClick={() => setMobileOpen(false)}>
              <Button size="sm" className="mt-2 w-full cursor-pointer">
                Launch Scanner
              </Button>
            </Link>
          </div>
        </nav>
      )}
    </header>
  )
}
