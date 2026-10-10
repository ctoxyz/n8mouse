# Releasing n8Mouse+

1. Bump `VERSION` in `n8mouse.py` and `version` in `pyproject.toml`.
2. `git tag v0.3.0 && git push --tags`
   GitHub Actions builds `n8mouse-windows-x64.zip` and `n8mouse-macos-arm64.zip`
   (each with a `.sha256`) and publishes the release.
3. **winget:** put the new version and the Windows `.sha256` into `packaging/winget/*.yaml`,
   then `wingetcreate submit packaging/winget` (opens a PR to microsoft/winget-pkgs).
   After it merges: `winget install n8dog.n8mouse`.
4. **Homebrew:** copy `packaging/homebrew/n8mouse.rb` into your `homebrew-tap` repo
   under `Casks/`, with the new version and the macOS `.sha256`.
   Then: `brew install --cask ctoxyz/tap/n8mouse`.
5. **PyPI (optional):** `python -m build && twine upload dist/*`
   Then: `pipx install n8mouse` or `uvx n8mouse`.

Replace `ctoxyz` with your GitHub user or org everywhere.
