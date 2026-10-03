export type Cve = {
  id: string
  description: string
  published: string
  cvss_score: number | null
  cvss_severity: string | null
  cvss_vector: string | null
  epss_score: number | null
  epss_percentile: number | null
  in_kev: boolean
  kev_due_date: string | null
  weaknesses: string[]
  affected_products: string[]
}

declare module 'claude-code' {
  interface PluginState {
    'cve-hover': { cves: Record<string, Cve | 'loading' | 'missing'> }
  }
}
