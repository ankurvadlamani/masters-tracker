# Masters Tracker

Live site: https://ankurvadlamani.github.io/masters-tracker/

A tracker for my European master's applications, covering requirements, deadlines, links, document checklists and status.
Anyone with the link can view it. Editing needs the password, and each edit is committed to `data.json` in this repo, so it syncs across devices.

## Files
- `index.html`: the app
- `data.json`: all the tracker data
- `secret.json`: the GitHub token encrypted with the edit password (AES-GCM, PBKDF2-SHA256, 600k iterations). It's created on first unlock.

## First-time setup
1. Create a fine-grained token: GitHub Settings → Developer settings → Fine-grained tokens. Set Repository access to **Only masters-tracker** and Permissions to **Contents: Read and write**.
2. Open the site and click **Unlock**. Paste the token, enter your password and click **Encrypt & save**.
3. From then on, on any device, you only need the password.

## Security
A 4-digit password could be brute-forced offline from `secret.json`. Because of that, the token only has access to this repo's contents, so the worst case is an unwanted edit that you can revert from the git history. To tighten this, set a longer password in Settings.
