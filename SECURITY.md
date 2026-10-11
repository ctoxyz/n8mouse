# Security

## Reporting a problem

Please do not open a public issue for a security problem.

Report it privately: go to the Security tab of this repository and choose
"Report a vulnerability", or use
https://github.com/ctoxyz/n8mouse/security/advisories/new

Only the latest release gets fixes.

## What n8Mouse+ protects against

- Someone on your network reading your keystrokes or clipboard: all traffic is TLS 1.3.
- Someone on your network connecting without the pairing code, or posing as your host.
- Guessing the pairing code: 16 characters, slow to test, repeated failures are blocked.

## What it does not protect against

- A computer you paired, or anyone holding the pairing code. They are fully trusted:
  they can type on your computers and they receive what you copy.
- Malware or another person already using your account on one of the computers.
- The downloads are not code-signed yet. Check the .sha256 file next to each download.
