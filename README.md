# amalgan8 mobile (React Native CLI)

The n8dog.com collective brain as a native app. Same terminal aesthetic, same
`{amalgan8}` wordmark, same per-section accents, every menu item, and a live
search that hits the production Lambda. Pure React Native, zero extra npm deps.

## Drop it into a fresh CLI project

```
npx @react-native-community/cli init amalgan8mobile
```

Then copy these over the scaffold:

- `App.js`            -> replace the generated one (delete `App.tsx` if a TS template was made)
- `src/`              -> the whole folder
- `assets/fonts/`     -> the four JetBrains Mono `.ttf` files
- `react-native.config.js`

Link the bundled font (one command), then run:

```
npx react-native-asset
npx react-native run-android      # or run-ios
```

`npx react-native-asset` copies the fonts into the native projects so the
terminal face renders. If you skip it, flip `USE_JBM` to `false` at the top of
`src/theme.js` and it falls back to the platform monospace (Menlo / Roboto Mono).
Font weight selection (`fontWeight`) maps to the right JetBrains Mono cut on
React Native 0.71+.

## Layout

```
App.js                     header (wordmark + section badge), nav strip, router
src/theme.js               all colors, fonts, per-section accents — reskin here
src/api.js                 every backend call (live Lambda Function URL)
src/ui.js                  wordmark, icons, pills, search bar, nav, scan loader
src/SearchSection.js       search bar -> scanning loader -> results
src/results/ResultsView.js YOU / ANSWER / probes / engines / job cards
src/screens/
  HomeScreen.js            collective brain: ask/teach + floating questions
  JobsScreen.js            blue: hero, ATS banner, trending, AI roles
  RentalsScreen.js         teal: hero, trending rentals, by-type
  LoveScreen.js            AI companions (live /dating/browse-public)
  LawScreen.js             ExParteAI legal drafting
  LabScreen.js             experiments
  HelpScreen.js            FAQ
  OntologyScreen.js        SENTINEL deterministic drone ops
```

## Endpoints

- `POST /search` `{ query }` powers ask/teach, jobs, and rentals (the brain routes by intent).
- `GET /dating/browse-public` powers the love screen.
- law / lab / help / ontology are presentational, matching the site sections.

Base URL is the Lambda Function URL in `src/api.js` (bypasses the API Gateway
29s timeout). `setToken()` is wired for a future Bearer token.

Results render defensively — they read whatever keys the brain returns
(`rich_results` / `jobs` / `engines` / `probes` / salary / source / url), so the
UI holds up as the payload shape evolves.
