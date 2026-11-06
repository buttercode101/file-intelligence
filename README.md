# File Intelligence

Proactive file scanning and actionable proposals for Hermes — finds duplicates, large files and sensitive items, then proposes ranked safe cleanup actions in Desktop. Dry-run by default; every mutation requires explicit approval via agent tools. **No silent tracking, moving or deleting.**

## Differentiation (Rule 16)
- **Bundled `disk-cleanup`**: silently tracks test/temp files *created* by the agent (`pre/post_tool_call`), cleans on session end. No scanning, no Desktop pane, no proposals.
- **`file-tray`** (catalog): tracks files the agent *touched* via read/write/patch.
- **`filebox`** (catalog): file browser CRUD.
- **This plugin:** proactive *scan* (stat + chunked hash) → *rank* → *propose* → *approve* → *archive*. No browser, no silent tracking.

## Tools
- `file_scan(root)` — read-only scan (depth, size, ignore patterns, resumable cursor, 10k cap)
- `file_propose(root)` — ranked proposals: duplicates (low), large >100MB (medium), sensitive (flag-only, high)
- `file_apply(paths, root, dry_run=true)` — **dry-run default**. Real apply = archive (rename) to `<root>/.file-intelligence-archive/`, reversible. Sensitive paths refused. No permanent delete in v1.

## Hooks
- `post_tool_call` — audit observer for `file_apply` only, fail-open

## Desktop
- Timeline pane: **static entry point** (read-only). It does not yet fetch `/proposals` — scan/proposal results are returned as tool output from `file_scan`/`file_propose` in chat. Backend `GET /status|proposals|audit` endpoints exist for future UI wiring.
- Status-bar chip
- Backend: `GET /api/plugins/file-intelligence/status|proposals|audit` — **read-only**. Mutations only via agent tools so approvals fire.

## Storage
SQLite in `ctx.state.data_dir` (`file_intelligence.db`), WAL, schema v1. **Metadata only (path, size, SHA-256 hash) — never file content.** Audit capped at 10k rows.

## Disclosure —
- Scans a user-specified directory (stat + full SHA-256 hash of contents in 1MB chunks for duplicate detection; files >1GB skipped for hashing with warning; **sensitive files are never hashed**). Hidden directories (dot-dirs) are excluded wholesale; hidden files at the scanned root (e.g. `.env`) are included and flagged sensitive
- Reads only file metadata and content for hashing; stores no file content
- `file_apply` with `dry_run=false` renames files into `<root>/.file-intelligence-archive/` (reversible archive, same filesystem)
- Sensitive files (`.env`, `*.pem`, `*.key`, `id_rsa`, etc.) are flagged only and **never moved**
- No network calls. No silent background cleanup.
- Nearest neighbours: bundled `disk-cleanup`, catalog `file-tray` / `filebox` (see Differentiation above)

## Validation
```bash
python3 tests/test_file_intelligence.py
hermes plugins validate --json .
hermes plugins doctor --ci .
```

## Demo (80s, mocked where noted)
1. Prompt: "Scan ~/Downloads for duplicates, large files, and anything sensitive. Propose only safe actions. Wait for approval."
2. Desktop pane populates (duplicate group + `.env` flag).
3. Approve one duplicate archive (dry-run preview, then apply via tool).
4. Updated totals + audit entry.
5. Sensitivity warning still visible.

## License
MIT
