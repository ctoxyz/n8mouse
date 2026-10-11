# Releasing n8Mouse+

Tags starting with `v` cannot be deleted and `main` cannot be force-pushed.
A bad release is fixed with a new version number, so finish the checks before you tag.

## Before you tag

1. Bump `VERSION` in `n8mouse.py`, `version` in `pyproject.toml`, and the version in
   `packaging/winget/*.yaml` and `packaging/homebrew/n8mouse.rb`.
2. `python tests/security_check.py` must end with every check passing.
3. `pip-audit` on the pinned versions in `.github/workflows/release.yml`: no known vulnerabilities.
4. Search what you are about to push for personal data: names, real computer names,
   real IP addresses, local paths, real pairing codes. Never fix a leak with a force-push:
   the old commit stays reachable on GitHub. Ask GitHub Support to purge it instead.
5. Test on real machines from source: `setup host` on Windows, `setup client` on a Mac
   and a Windows PC. Edge switch, typing, copy and paste both ways, ScrollLock,
   Ctrl+Alt+N, drop the Wi-Fi (control returns within 6 seconds), reboot (starts by itself).

## Release

1. `git tag vX.Y.Z` then `git push origin vX.Y.Z`.
   GitHub Actions builds `n8mouse-windows-x64.zip` and `n8mouse-macos-arm64.zip`
   (each with a `.sha256`) and publishes the release.
2. Download both zips, confirm the SHA-256 matches the `.sha256` files, and install
   from the zips on one Windows PC and one Mac exactly as the README says.

## Package managers

After the release is published:

1. `powershell -ExecutionPolicy Bypass -File packaging\update-hashes.ps1`
   downloads both zips, checks them against their `.sha256` files, and writes the hashes
   into `packaging/winget/n8dog.n8mouse.installer.yaml` and `packaging/homebrew/n8mouse.rb`.
   Commit and push those two files to `main`.
2. **winget:** `winget validate --manifest packaging\winget`, then
   `wingetcreate submit --token <GitHub token> packaging\winget`. It opens a pull request on
   microsoft/winget-pkgs. After it merges: `winget install n8dog.n8mouse`.
   The package ID `n8dog.n8mouse` is permanent once listed.
3. **Homebrew:** copy `packaging/homebrew/n8mouse.rb` to `Casks/n8mouse.rb` in
   github.com/ctoxyz/homebrew-tap and push. Then: `brew install --cask ctoxyz/tap/n8mouse`.
   The cask removes the macOS quarantine flag after install, because the app is unsigned.
4. **PyPI (optional):** `python -m build && twine upload dist/*`.

Forking? Replace `ctoxyz` with your GitHub user or org everywhere.
