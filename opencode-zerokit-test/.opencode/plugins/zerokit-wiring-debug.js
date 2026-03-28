import { mkdir, writeFile } from "node:fs/promises"
import { join } from "node:path"

const EXPECTED_INSTRUCTIONS = [
  "AGENTS.md",
  ".agent/agent.md",
  ".agent/HARNESS_SCOPE.md",
  ".agent/methodology/master-harness.md",
  ".agent/methodology/phases/*.md",
]

async function writeMarker(baseDir, body) {
  const debugDir = join(baseDir, ".zerokit-debug")
  await mkdir(debugDir, { recursive: true })
  await writeFile(
    join(debugDir, "wiring.json"),
    `${JSON.stringify(body, null, 2)}\n`,
    "utf8",
  )
}

export const ZerokitWiringDebug = async ({ directory, worktree, project }) => {
  const baseDir =
    process.env.ZEROKIT_TEST_PROJECT_ROOT || worktree || directory || process.cwd()
  const markerBase = {
    generated_at: new Date().toISOString(),
    directory,
    worktree,
    project,
    config_dir: process.env.OPENCODE_CONFIG_DIR || null,
    expected_instructions: EXPECTED_INSTRUCTIONS,
  }

  await writeMarker(baseDir, {
    ...markerBase,
    event: "plugin.initialized",
  })

  return {
    "session.created": async () => {
      await writeMarker(baseDir, {
        ...markerBase,
        generated_at: new Date().toISOString(),
        event: "session.created",
      })
    },
  }
}
