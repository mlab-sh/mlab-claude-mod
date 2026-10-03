import { atom, read, update } from 'claude-code'
import type { Engine, Register } from 'claude-code'

import type { Cve } from '../types'

const API = 'https://vuln.mlab.sh/api/v1/cve/'
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi
const cves = atom({ plugin: 'cve-hover', key: 'cves' } as const, {})

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'magenta',
  HIGH: 'red',
  MEDIUM: 'yellow',
  LOW: 'green',
}

const cut = (t: string, n: number) => (t.length > n ? `${t.slice(0, n - 1)}…` : t)
const pct = (n: number | null) => (n == null ? '?' : `${(n * 100).toFixed(1)}%`)

// Fetch once per CVE; result lands in state, which redraws chips and cards.
async function ensure($: Engine, id: string) {
  let isNew = false
  await update($, cves, all => {
    if (all[id]) return all
    isNew = true
    return { ...all, [id]: 'loading' }
  })
  if (!isNew) return

  let value: Cve | 'missing' = 'missing'
  try {
    const res = await $.http.fetch(API + id, { headers: { accept: 'application/json' } })
    if (res.ok) {
      const d = JSON.parse(res.text)
      value = {
        id: String(d.id ?? id),
        description: String(d.description ?? '').replace(/\s+/g, ' ').trim(),
        published: String(d.published ?? '').slice(0, 10),
        cvss_score: d.cvss_score ?? null,
        cvss_severity: d.cvss_severity ?? null,
        cvss_vector: d.cvss_vector ?? null,
        epss_score: d.epss_score ?? null,
        epss_percentile: d.epss_percentile ?? null,
        in_kev: Boolean(d.in_kev),
        kev_due_date: d.kev_due_date ?? null,
        weaknesses: (d.weaknesses ?? []).slice(0, 5),
        affected_products: (d.affected_products ?? []).slice(0, 5),
      }
    }
  } catch {
    // ponytail: no retry; a failed lookup stays "missing" for the session.
  }
  await update($, cves, all => ({ ...all, [id]: value }))
}

// Hidden card floating above its chip (absolute: overlays the reply, moves nothing).
// Revealed by the chip's own keyed Box, so only the hovered chip opens it.
// ponytail: kept ~7 rows tall; a reply shorter than that clips the card's top.
function Card({ c, ui }: { c: Cve; ui: { Box: any; Text: any } }) {
  const { Box, Text } = ui
  const color = SEVERITY_COLOR[c.cvss_severity ?? ''] ?? 'gray'
  return (
    <Box
      position="absolute"
      bottom={1}
      left={0}
      width={72}
      backgroundColor="black"
      display="none"
      hover={{ display: 'flex' }}
      flexDirection="column"
      borderStyle="round"
      borderColor={color}
      paddingX={1}
    >
      <Text bold color={color}>
        {c.id} · {c.cvss_severity ?? 'N/A'} {c.cvss_score ?? ''}
        {c.in_kev ? `  · CISA KEV${c.kev_due_date ? ` (due ${c.kev_due_date})` : ''}` : ''}
      </Text>
      <Text dimColor>
        Published {c.published} · EPSS {pct(c.epss_score)} (p{pct(c.epss_percentile)})
        {c.weaknesses.length ? ` · ${c.weaknesses.join(', ')}` : ''}
      </Text>
      <Text>{cut(c.description, 200)}</Text>
      {c.affected_products.length ? (
        <Text dimColor wrap="truncate-end">Affects: {c.affected_products.join(', ')}</Text>
      ) : null}
      <Text color="cyan">https://vuln.mlab.sh/cve/{c.id}</Text>
    </Box>
  )
}

export const register: Register = on => {
  // Assistant text: keep the markdown, add a row of hoverable CVE chips under it.
  on('ui.render', { component: 'AssistantMessage' }, async ($, e, next) => {
    const ids = [...new Set((e.props.text.match(CVE_RE) ?? []).map(s => s.toUpperCase()))]
    if (ids.length === 0) return next(e)

    for (const id of ids) void ensure($, id)
    const all = await read($, cves)
    const { Box, Text, Markdown } = $.ui.resolve(e)

    return (
      <Box flexDirection="column">
        <Markdown text={e.props.text} />
        <Box flexWrap="wrap">
          {ids.map(id => {
            const c = all[id]
            const color =
              typeof c === 'object' ? (SEVERITY_COLOR[c.cvss_severity ?? ''] ?? 'gray') : 'gray'
            const badge =
              typeof c === 'object'
                ? ` ${c.cvss_score ?? '?'}${c.in_kev ? ' KEV' : ''}`
                : c === 'missing' ? ' ?' : ' …'
            return (
              <Box key={id}>
                <Text color={color} hover={{ inverse: true }}>
                  {` ⚠ ${id}${badge} `}
                </Text>
                {typeof c === 'object' ? Card({ c, ui: { Box, Text } }) : null}
              </Box>
            )
          })}
        </Box>
      </Box>
    )
  })
}
