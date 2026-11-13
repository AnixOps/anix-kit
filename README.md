# AnixOps Kit

Shared Go building blocks for every AnixOps product (Control, Agent,
speedtest and future services). A package lands here only when at least two
products use it, or when a new product would otherwise write it again.

The kit depends on no product; products depend on the kit and pin it by
version in their `go.mod`.

| Package | What it does |
| --- | --- |
| `sign` | Ed25519 signing and verification in the AnixOps format: base64 raw public keys, base64 detached signatures, PKCS#8 PEM private keys, 16-hex public key ids |
| `cmd/anixsign` | Command line for the same format (keygen, pub, id, digest, sign, verify): `go run github.com/AnixOps/anix-kit/cmd/anixsign@<version>` |
| `update` | The signed update feed every AnixOps updater reads (format `anixops-appcast-v1`, first shipped by AnixOps Net for macOS): envelope, feed and archive signatures, replay and downgrade checks, choosing the newest item |
| `cmd/anixupdate` | Release-side command for the feed (item, feed, verify): `go run github.com/AnixOps/anix-kit/cmd/anixupdate@<version>` |
| `redact` | Removes personal data (URLs, e-mail, IPs, UUIDs, key-like tokens, host names, home directory and account name) from crash reports, diagnostics and logs; the same rules as the AnixOps Net client, checked against shared vectors in `redact/testdata/vectors.json` |

Reusable GitHub workflows live in `.github/workflows` and are called with
`uses: AnixOps/anix-kit/.github/workflows/<file>@<ref>`:

- `signing-key-check.yml`: checks that the signing secrets are a working pair (and the key the caller trusts).

Commercial-only code (licenses, quota guards) lives in the private
`anix-commercial-kit`, never here.

## License

Apache License 2.0, see [LICENSE](LICENSE).
