# Vendored: cloudflare/security-audit-skill

- **Source:** https://github.com/cloudflare/security-audit-skill (`skills/security-audit/`)
- **Commit:** `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` (2026-09-14)
- **License:** MIT (see `LICENSE` in this folder)
- **Used by:** `lib/security-audit.js` (`audit.js`). The
  validators are called through `lib/audit-validate.cjs`, which runs them
  unchanged where `O_NOFOLLOW` exists. On Windows it uses a portable safe read
  plus their exported `validateDocument`.

The files are unmodified copies. The upstream validator tests
(`*.test.cjs`) are left out.

## Updating

Updating is an org decision. Make the change by PR, then tag a new tool release.

```bash
git clone --depth 1 https://github.com/cloudflare/security-audit-skill /tmp/sas
cp /tmp/sas/skills/security-audit/{*.md,report-schema.json,validate-findings.cjs,validate-coverage-ledger.cjs} vendor/security-audit/
cp /tmp/sas/LICENSE vendor/security-audit/LICENSE
git -C /tmp/sas log -1 --format='%H %cs'   # paste into "Commit" above
```

After updating, read the upstream changes to `SKILL.md`. Check that
`lib/security-audit.js` still matches what the skill expects: the file names it
writes, `run-metadata.json` fields and the validator command lines.
