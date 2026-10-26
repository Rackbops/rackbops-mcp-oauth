import { execFileSync } from "node:child_process"
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { afterEach, describe, expect, it } from "vitest"

const scriptsDir = dirname(fileURLToPath(import.meta.url))

function nextVersion(current: string, stdin: string): string {
  return execFileSync("bash", [join(scriptsDir, "next-version.sh"), current], {
    input: stdin,
    encoding: "utf8",
  }).trim()
}

describe("next-version.sh", () => {
  it("bumps the minor for a breaking marker behind a squash-body list bullet", () => {
    expect(nextVersion("0.1.4", "fix(x): y (#1)\n\n* fix(x)!: z\n* chore: w")).toBe("0.2.0")
    expect(nextVersion("0.1.4", "- feat!: z")).toBe("0.2.0")
  })

  it("still bumps the minor for a bare subject marker and a BREAKING CHANGE footer", () => {
    expect(nextVersion("0.1.4", "feat(x)!: z")).toBe("0.2.0")
    expect(nextVersion("0.1.4", "fix: z\n\nBREAKING CHANGE: gone")).toBe("0.2.0")
  })

  it("bumps the patch with no breaking marker", () => {
    expect(nextVersion("0.1.4", "fix: z\n\n* fix: y\n* chore: w")).toBe("0.1.5")
  })
})

describe("release.sh (dry run)", () => {
  const dirs: string[] = []
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
  })

  // A scratch repo holding copies of the scripts, tagged v0.1.4, with the given commits on top.
  function release(commits: Array<{ message: string; files: Record<string, string> }>): string {
    const repo = mkdtempSync(join(tmpdir(), "release-test-"))
    dirs.push(repo)
    const git = (...args: string[]) =>
      execFileSync("git", ["-C", repo, ...args], { encoding: "utf8" })
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    mkdirSync(join(repo, ".github/scripts"), { recursive: true })
    mkdirSync(join(repo, "src"))
    for (const f of ["release.sh", "next-version.sh"]) {
      copyFileSync(join(scriptsDir, f), join(repo, ".github/scripts", f))
      chmodSync(join(repo, ".github/scripts", f), 0o755)
    }
    writeFileSync(join(repo, "package.json"), '{\n  "version": "0.1.4"\n}\n')
    writeFileSync(join(repo, "src/a.ts"), "export {}\n")
    git("add", "-A")
    git("commit", "-q", "-m", "chore(release): v0.1.4")
    git("tag", "v0.1.4")
    for (const c of commits) {
      for (const [path, content] of Object.entries(c.files)) {
        writeFileSync(join(repo, path), content)
      }
      git("add", "-A")
      git("commit", "-q", "-m", c.message)
    }
    return execFileSync("bash", [".github/scripts/release.sh"], {
      cwd: repo,
      encoding: "utf8",
      env: { ...process.env, RELEASE_DRY_RUN: "1" },
    }).trim()
  }

  it("proposes a patch release for a package.json-only fix", () => {
    const out = release([
      {
        message: "fix(pkg): exports",
        files: { "package.json": '{\n  "version": "0.1.4","x":1\n}\n' },
      },
    ])
    expect(out).toContain("Dry run: 0.1.4 -> 0.1.5")
  })

  it("proposes nothing when the only new commit is a release bump commit", () => {
    const out = release([
      {
        message: "chore(release): v0.1.5",
        files: { "package.json": '{\n  "version": "0.1.5"\n}\n' },
      },
    ])
    expect(out).toContain("Nothing to do")
  })

  it("does not drop a real fix whose body mentions a chore(release): line", () => {
    const out = release([
      {
        message: "fix(x): real\n\nchore(release): v9 mention",
        files: { "src/a.ts": "export const a = 1\n" },
      },
    ])
    expect(out).toContain("Dry run: 0.1.4 -> 0.1.5")
  })

  it("ignores a chore(deps) bump that only edits package.json, but not one touching src/", () => {
    const pkg = { "package.json": '{\n  "version": "0.1.4","d":1\n}\n' }
    expect(release([{ message: "chore(deps): bump x", files: pkg }])).toContain("Nothing to do")
    expect(
      release([
        { message: "chore(deps): bump x", files: { ...pkg, "src/a.ts": "export const b = 1\n" } },
      ]),
    ).toContain("Dry run")
  })

  it("releases a chore(deps) bump of a shipped dependency or peer dependency", () => {
    const dep = { "package.json": '{\n  "version": "0.1.4","dependencies":{"a":"2"}\n}\n' }
    expect(release([{ message: "chore(deps): bump a", files: dep }])).toContain("Dry run")
  })

  it("releases a chore(deps) bump that changes only peerDependencies", () => {
    const peer = {
      "package.json": '{\n  "version": "0.1.4","peerDependencies":{"hono":">=5"}\n}\n',
    }
    expect(release([{ message: "chore(deps): widen hono", files: peer }])).toContain("Dry run")
  })

  it("proposes nothing for a commit outside src/ and package.json", () => {
    const out = release([{ message: "docs: x", files: { "README.md": "x\n" } }])
    expect(out).toContain("Nothing to do")
  })
})
