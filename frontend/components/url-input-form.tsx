"use client"

import { useState } from "react"
import { Search, Scan, Swords, FileText, Phone } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"

const actions = [
  { value: "scan" as const, label: "Scan", icon: Scan, description: "Discover endpoints" },
  { value: "attack" as const, label: "Attack", icon: Swords, description: "Run security tests" },
  { value: "report" as const, label: "Report", icon: FileText, description: "Generate report" },
  { value: "call" as const, label: "Call", icon: Phone, description: "Make API request" },
]

type Action = "scan" | "attack" | "report" | "call"

interface URLInputFormProps {
  onSubmit: (url: string, action: Action) => void
  isLoading: boolean
}

export function URLInputForm({ onSubmit, isLoading }: URLInputFormProps) {
  const [url, setUrl] = useState("")
  const [selectedAction, setSelectedAction] = useState<Action>("scan")

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!url.trim()) return
    onSubmit(url.trim(), selectedAction)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Action selector */}
      <div>
        <label className="mb-2 block text-sm font-medium text-foreground">
          Select Action
        </label>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {actions.map((action) => (
            <button
              key={action.value}
              type="button"
              onClick={() => setSelectedAction(action.value)}
              className={cn(
                "flex flex-col items-center gap-1.5 rounded-lg border p-4 text-sm transition-all cursor-pointer",
                selectedAction === action.value
                  ? "border-primary bg-primary/10 text-primary"
                  : "border-border bg-card text-muted-foreground hover:border-primary/30 hover:text-foreground"
              )}
            >
              <action.icon className="h-5 w-5" />
              <span className="font-medium">{action.label}</span>
              <span className="text-xs opacity-70">{action.description}</span>
            </button>
          ))}
        </div>
      </div>

      {/* URL input */}
      <div>
        <label
          htmlFor="target-url"
          className="mb-2 block text-sm font-medium text-foreground"
        >
          Target URL
        </label>
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              id="target-url"
              type="url"
              placeholder="https://api.example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="pl-10"
              required
            />
          </div>
          <Button type="submit" disabled={isLoading || !url.trim()} className="cursor-pointer">
            {isLoading ? (
              <span className="flex items-center gap-2">
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                Running...
              </span>
            ) : (
              `Run ${actions.find((a) => a.value === selectedAction)?.label}`
            )}
          </Button>
        </div>
      </div>

      <p className="text-xs text-muted-foreground">
        {/* In production, this would call the Rico backend API */}
        This demo uses simulated data. Connect to a real Rico backend for live
        scanning results.
      </p>
    </form>
  )
}
