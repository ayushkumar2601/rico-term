import type { Metadata, Viewport } from "next"
import { Geist, Geist_Mono } from "next/font/google"

import { Header } from "@/components/header"
import { Footer } from "@/components/footer"
import "./globals.css"

const _geist = Geist({ subsets: ["latin"] })
const _geistMono = Geist_Mono({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: {
    default: "Rico - AI-Driven API Security Scanner",
    template: "%s | Rico",
  },
  description:
    "Rico is an AI-powered API security scanner that discovers, classifies, and tests your API endpoints for vulnerabilities.",
}

export const viewport: Viewport = {
  themeColor: "#0f1117",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body className="font-sans antialiased min-h-screen flex flex-col">
        <Header />
        <main className="flex-1">{children}</main>
        <Footer />
      </body>
    </html>
  )
}
