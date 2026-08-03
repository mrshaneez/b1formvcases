# Section B1 - Case Manager

Case-management web app for the High Court of the Maldives (Section B1).
Single static file - no build step.

## Files
- index.html    - the app (contains NO case data; safe to be public)
- config.json   - points every device at the sign-in server (no secret inside)

## Hosting
Cloudflare Pages -> https://cases.mvcases.com . Any commit here auto-redeploys.

## Sign-in server
Cloudflare Worker at https://signin.mvcases.com (project b1-signin).
Case data now syncs across devices through this server; the admin secret lives
only on the Worker and on admin devices - never in this repo.

## Do NOT commit
- registry-cases.json (real case data / PII)
- any *-with-cases.html
- the server SECRET
