from __future__ import annotations

import getpass

from src.identity import verify_identity


def main() -> None:
    print("Technocore Sentinel — local identity verifier")
    print("Your phrase/seed is read only in this local process and is never printed.")
    did = input("Existing DID (did:key:z6Mk...): ").strip()
    secret = getpass.getpass("Phrase / 64-hex Ed25519 seed: ")
    check = verify_identity(did, secret)
    print(f"Derived DID: {check.derived_did}")
    if check.matches:
        print("MATCH: this secret derives the configured DID using Technocore's official signer convention.")
    else:
        print("MISMATCH: do NOT enable signed posting with this secret. The generator may use a different derivation.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
