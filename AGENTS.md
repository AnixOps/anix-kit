# Agent rules

- Keep the code lightweight: only necessary checks, no speculative options,
  no extra branches. Reuse the standard library first.
- No third-party code or copied examples; reference sources by link only.
- Nothing about private kernels or private protocols goes into this public
  repository: code, docs, comments or commit messages.
- A change to a format (key encoding, signature encoding, key id) breaks
  every deployed product that verifies with it. Formats only grow; never
  change an existing one.
- CI (`.github/workflows/ci.yml`) is the source of truth for gofmt, vet and
  tests.
