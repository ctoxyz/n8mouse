# Goes in your tap repo: github.com/ctoxyz/homebrew-tap/Casks/n8mouse.rb
# Users install with:  brew install --cask ctoxyz/tap/n8mouse
cask "n8mouse" do
  version "0.4.1"
  sha256 "REPLACE_WITH_n8mouse-macos-arm64.zip.sha256"

  url "https://github.com/ctoxyz/n8mouse/releases/download/v#{version}/n8mouse-macos-arm64.zip"
  name "n8Mouse+"
  desc "Share one keyboard, mouse and clipboard across your computers"
  homepage "https://github.com/ctoxyz/n8mouse"

  depends_on arch: :arm64

  app "n8mouse.app"
  binary "#{appdir}/n8mouse.app/Contents/MacOS/n8mouse"

  uninstall launchctl: "com.n8mouse.agent"

  zap trash: [
    "~/Library/Application Support/n8mouse",
    "~/Library/LaunchAgents/com.n8mouse.agent.plist",
  ]
end
