# Section B1 - Case Manager

Case-management web app for the High Court of the Maldives (Section B1).
Single static file - no build step.

## Files in this repo
- index.html    - the app (contains NO case data; safe to be public)
- config.json   - points every device at the sign-in server (no secret inside)

## Hosting
Served by Cloudflare Pages at https://cases.mvcases.com .
Any commit here auto-redeploys.

## Sign-in server
Cloudflare Worker at https://signin.mvcases.com (project b1-signin).
The admin secret lives only on the Worker and on admin devices - never in this repo.

## Loading cases
The deployed index.html has no case data. Sign in, then Import / export -> paste
registry-cases.json -> Import. Case data then lives in the app and syncs via the
sign-in server - never in this repo.

## Do NOT commit
- registry-cases.json (real case data / PII)
- any file with cases embedded
- the server SECRET
