# n8Mouse+

One keyboard and mouse for every computer on your desk. Copy on one, paste on any.
Free and open source (MIT). No accounts, no licence server, no cloud.

## Install - two commands per machine

**1. The PC with the keyboard and mouse (Windows)**

    winget install n8dog.n8mouse
    n8mouse setup host

```
n8Mouse+ 0.4.0 setup - host 'DESKTOP'

  [1/3] settings saved     C:\Users\you\AppData\Roaming\n8mouse\n8mouse.json
  [2/3] firewall           approve the Windows admin prompt...
                           opened for the local network
  [3/3] start at login     on, running now

  Pairing code:  K7QM-4XZP-9WRT-HC3N

  On each other computer run:
      n8mouse setup client K7QM-4XZP-9WRT-HC3N
```

**2. Every other computer**

Mac:

    brew install --cask ctoxyz/tap/n8mouse
    n8mouse setup client K7QM-4XZP-9WRT-HC3N

Windows:

    winget install n8dog.n8mouse
    n8mouse setup client K7QM-4XZP-9WRT-HC3N

```
n8Mouse+ 0.4.0 setup - client 'macbook'

  [1/3] looking for the host on the network...
  [1/3] paired with host   DESKTOP (192.168.1.10)
  [2/3] settings saved     /Users/you/Library/Application Support/n8mouse/n8mouse.json
  [3/3] start at login     on, running now

  macOS will ask to let n8Mouse+ control this computer.
  Click 'Open System Settings' and switch n8Mouse+ on under Accessibility.

  Done. Push the mouse off the host's screen edge to reach this computer.
```

That's it. Everything starts at login from now on.
The host is found automatically; if your network blocks that, add its IP:
`n8mouse setup client K7QM-4XZP-9WRT-HC3N 192.168.1.10`

Python users (3.13 or newer): `pipx install n8mouse` works on both platforms.

## Use

- Push the pointer off a screen edge to move to the next computer.
- Computers line up left to right in the order they connect.
- **ScrollLock** on the host keyboard: back to the host.
- **Ctrl+Alt+1..9**: jump straight to screen N.
- Copy on any computer, paste on any other (text).

## Commands

| Command | |
|---|---|
| `n8mouse setup host` | Once, on the keyboard/mouse PC |
| `n8mouse setup client <CODE> [ip]` | Once, on every other computer |
| `n8mouse stop` | Stop until next login |
| `n8mouse uninstall` | Remove start-at-login and firewall rules |
| `n8mouse` | Run now in the role chosen at setup |

## Custom layout

Edit `"layout"` in the host's `n8mouse.json` (path shown by setup). Names are computer
names, not case sensitive; the reverse side is filled in for you.

    "layout": {
      "DESKTOP":  { "right": "macbook", "top": "laptop2" },
      "macbook": { "right": "laptop1" }
    }

## Security

- Every connection is encrypted with TLS 1.3, keyed from the pairing code.
- Both sides prove they hold the code during the handshake; the code itself never crosses the network.
  A device that does not have it cannot connect, cannot read traffic, and cannot pose as the host.
- 16-character pairing codes (~80 bits), stretched with scrypt.
- Repeated wrong codes from one address are blocked for a minute.
- The pairing code is stored only in your user settings file (owner-only on macOS).
- Anyone holding the pairing code can join. Treat it like a Wi-Fi password;
  to change it, delete `n8mouse.json` on the host, run `n8mouse setup host`, and re-pair each computer.

## Limits

- Clipboard is text only.
- Each computer counts as one screen, however many monitors it has.
- The host must be Windows for now.

Logs: `n8mouse.log` next to `n8mouse.json`.
