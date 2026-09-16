---
'@generaltranslation/api': minor
'generaltranslation': minor
'gt': minor
---

Add `gt login`, `gt logout`, and `gt whoami`. Login uses OAuth 2.1 authorization code with PKCE against the General Translation dashboard, signing in as the well-known `gt-cli` public client and receiving the redirect on a loopback listener. Where no browser can reach the CLI (`--no-browser`, SSH, or a loopback port that cannot bind) it falls back to the OAuth device grant: enter the short code shown in the terminal at the dashboard's `/device` page. Tokens are stored per authorization server in `~/.config/gt/credentials.json` (0600) and refreshed silently. The API client and core request path accept a refreshable user-token provider, used only when no API key is configured — an explicit API key always wins.
