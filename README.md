# AnixOps Kit

Shared Go building blocks for every AnixOps product (Control, Agent,
speedtest and future services). A package lands here only when at least two
products use it, or when a new product would otherwise write it again.

The kit depends on no product; products depend on the kit and pin it by
version in their `go.mod`.

| Package | What it does |
| --- | --- |
| `sign` | Ed25519 signing and verification in the AnixOps format: base64 raw public keys, base64 detached signatures, PKCS#8 PEM private keys, 16-hex public key ids |
| `cmd/anixsign` | Command line for the same format (keygen, pub, id, sign, verify) |

Reusable GitHub workflows live in `.github/workflows` and are called with
`uses: AnixOps/anix-kit/.github/workflows/<file>@<ref>`.

Commercial-only code (licenses, quota guards) lives in the private
`anix-commercial-kit`, never here.

## License

Apache License 2.0, see [LICENSE](LICENSE).
