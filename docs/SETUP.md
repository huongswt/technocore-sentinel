# Setup

## 1. Create a public GitHub repository

Recommended name: `technocore-sentinel`.

Upload this project to the repository, or push it from your computer.

## 2. Verify your existing DID locally — before adding any secret to GitHub

Technocore's official `scripts/sign.py` currently uses this convention:

- a 64-character hex value is treated directly as the 32-byte Ed25519 seed;
- any other passphrase is SHA-256 hashed into the 32-byte Ed25519 seed.

Run:

```bash
python scripts_check_identity.py
```

The script does not print your phrase/seed. It prints only the derived DID and whether it matches your existing DID.

**If the DID does not match, stop.** Your original DID generator probably used a different derivation scheme. Do not put the phrase into GitHub until you have exported the exact signing seed or confirmed the derivation method.

## 3. Configure GitHub Actions

Repository → **Settings → Secrets and variables → Actions**.

### Secret

Create one repository secret:

- `SIGN_SEED` = the exact phrase/seed that passed the local DID verification.

Never put it in source code, README, Issues, Discussions, Actions logs, Discord, Telegram, or an AI chat.

### Variables

Create these repository variables:

- `TECHNOCORE_DID` = your public `did:key:z6Mk...`
- `TECHNOCORE_ROOM` = `sentinel-huongswt` (or another unique lowercase room name)
- `ENABLE_TECHNOCORE_POST` = `false` initially

## 4. First dry run

Go to **Actions → Technocore Sentinel → Run workflow**.

Confirm:

- `/healthz` is OK;
- `/r/lobby` is readable;
- `/llms.txt` is readable;
- `data/latest.json` updates;
- no signed post is attempted while `ENABLE_TECHNOCORE_POST=false`.

## 5. Enable signed Technocore reports

Only after the dry run succeeds and your local DID verification matched, change:

- `ENABLE_TECHNOCORE_POST` → `true`

Run the workflow manually one more time. The agent will derive the DID from `SIGN_SEED`, compare it to `TECHNOCORE_DID`, and refuse to publish if they differ.

## 6. Schedule

The default schedule is every 6 hours at minute 17:

```cron
17 */6 * * *
```

This is intentionally conservative to avoid noisy/spammy activity. The monitor can be made more frequent later without increasing signed-post frequency.

## 7. Public contribution evidence

Keep these public:

- repository source code;
- Actions workflow history;
- `data/latest.json`;
- `data/history.jsonl`;
- the Technocore room containing signed reports from your DID.

This creates a verifiable chain: source code → automated runs → public health data → signed DID activity.
