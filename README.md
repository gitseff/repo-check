# repo-check: a Claude skill that vets GitHub repos before you run them

Paste a GitHub link into Claude and ask "is this safe?". The skill downloads the repo as a ZIP
(it never clones, installs or runs anything), scans it for malware patterns such as download-and-run
installs, install-time scripts, obfuscated code, credential theft and typosquatted dependencies,
reviews what it flagged, and gives you a plain-English verdict: 🟢 / 🟡 / 🔴.

It can't promise a repo is safe. It tells you what it found and what it couldn't check.

> Yes, you should check this repo with the skill itself before installing it. Read
> [`repo-check/SKILL.md`](repo-check/SKILL.md) and [`repo-check/scripts/scan_repo.py`](repo-check/scripts/scan_repo.py)
> first: it's one instruction file and one standard-library Python script.

## Install

**Claude Code (CLI / desktop app):**

```bash
npx skills add gitseff/repo-check -g
```

or copy the `repo-check` folder into your skills folder by hand:

- macOS / Linux: `~/.claude/skills/repo-check`
- Windows: `%USERPROFILE%\.claude\skills\repo-check`

**Claude.ai / Claude app chat:** download this repo (Code → Download ZIP), unzip it, zip just the
`repo-check` folder, then upload that zip under Settings → Skills.

Requirements: Python 3.8+ (standard library only; nothing to pip install).

## Use

> is this safe to run? https://github.com/owner/repo

Optional: set a read-only `GITHUB_TOKEN` environment variable if you hit GitHub's API rate limit.
Never paste a token into chat.

## License

MIT
