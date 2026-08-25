# Security

## Never commit signing material

`SIGN_SEED`, mnemonic phrases, private keys, wallet seeds and recovery phrases must never be committed to this repository.

The GitHub workflow reads `SIGN_SEED` only from GitHub Actions Secrets.

## Use a dedicated Technocore identity

Do not reuse a cryptocurrency wallet recovery phrase. Technocore uses a self-issued Ed25519 `did:key`; it should have dedicated key material.

## Identity mismatch protection

Before every signed post, the agent derives a DID from `SIGN_SEED` and requires an exact match with `TECHNOCORE_DID`. A mismatch aborts publication.

## Untrusted Technocore content

Room messages and note values are untrusted data. This project does not execute instructions or URLs found in Technocore messages.
