# Masters Journey

A private, end-to-end tracker for Ankur's master's applications: research → shortlist → documents → apply → decisions → finance → visa → departure → arrival.

Live: https://ankurvadlamani.github.io/masters-tracker/ (locked with a password)

## What's in here

| File | Public? | What it holds |
|---|---|---|
| `index.html`, `app.js`, `app.css` | yes | The app. Uses the portfolio's theme from `/assets/css/site.css`. |
| `research.json` | yes | Programme facts only: deadlines, requirements, fees, links, country visa/finance info, scholarships. |
| `updates.json` | yes | Written by the weekly Claude research run: corrected fields and a change log per programme. |
| `monitor.json` | yes | Written every day by the GitHub Action: which official pages changed and any new dates spotted on them. |
| `private.enc.json` | encrypted | Your profile, application stages, SOP status, notes, documents, visa checklist, milestones, custom programmes and your GitHub token. AES-GCM, key derived from your password (PBKDF2-SHA256, 600k rounds). |

Nothing personal is ever stored unencrypted. Anyone can read the public programme files; they only contain facts from university websites.

## Automation

1. **Daily page monitor** (`.github/workflows/monitor.yml`): every day at 08:00 India time GitHub fetches each programme's official pages (the `watch` list in `research.json`), notes when a page changes and pulls out new dates near words like "deadline" or "application". Changes show as alerts on the dashboard. Run it by hand from **Actions → Monitor programme pages → Run workflow**. GitHub pauses scheduled workflows after 60 days without repo activity; re-enable from the Actions tab if that happens.
2. **Weekly research run** (a Claude scheduled task): re-checks each programme's deadlines, requirements and fees on the official sites and writes corrections into `updates.json`. The app applies them on top of `research.json` and shows what changed and where it came from. Runs need your computer on with the Claude desktop app open.

## Saving from any device

Viewing works everywhere with the password. To **save** changes you connect a GitHub token once (it's stored inside the encrypted file, so every device gets it after unlocking):

1. Create a fine-grained token: https://github.com/settings/personal-access-tokens/new
   - Repository access: **Only select repositories → masters-tracker**
   - Permissions: **Contents → Read and write**
2. In the tracker: **Settings → Saving online**, paste it, press **Connect**.

**Disconnect** removes the token from the saved data. Change the password under **Settings → Password**.

## Editing programmes

Open any programme → **Edit** to change facts (saved to `research.json`), or **+ Add programme** for your own (kept private in the encrypted file).
