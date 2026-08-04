/**
 * Section case-manager — sign-in server (Cloudflare Worker)
 * =========================================================
 * A tiny backend that stores the user registry so people can sign in on ANY device,
 * and (optionally) emails new users their login details.
 *
 * WHAT IT DOES
 *  - Holds users (username, salted password hash, role, etc.) in Cloudflare KV.
 *  - Verifies logins server-side (password hashes never leave the server).
 *  - Lets the admin app create / list / delete / reset users (guarded by a shared secret).
 *  - Optionally sends the login email itself (via Resend). If you leave email to the app's
 *    Microsoft 365 mailbox instead, you don't need Resend at all.
 *
 * DEPLOY (about 10 minutes, all free):
 *  1. Create a free Cloudflare account → Workers & Pages → Create → Worker. Name it e.g. "b1-signin".
 *  2. Paste this whole file as the Worker code and Deploy.
 *  3. Storage: Workers & Pages → KV → Create namespace "USERS".
 *     Then in the Worker → Settings → Variables → KV Namespace Bindings:
 *       Variable name: USERS   Namespace: USERS
 *  4. Worker → Settings → Variables → Environment Variables (encrypt these):
 *       SECRET      = a long random password (the "server secret" you'll paste into the app)
 *       (optional) RESEND_KEY = your Resend API key, if you want the SERVER to send email
 *       (optional) FROM_EMAIL = a verified Resend sender, e.g. registry@yourcourt.gov.mv
 *  5. Copy the Worker URL (like https://b1-signin.YOURNAME.workers.dev) — paste it into the app
 *     under Users → Server, along with the SECRET.
 *
 * SECURITY: the SECRET guards user creation/listing. Login and self password-change are public
 * (they verify credentials). CORS is open so the static app can call it from the browser.
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function randSalt() {
  return [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, '0')).join('');
}
const keyOf = (u) => 'user:' + String(u).trim().toLowerCase();
function stripSecret(rec) { const { hash, salt, ...safe } = rec; return safe; }

async function sendResendEmail(env, to, subject, text) {
  if (!env.RESEND_KEY || !to) return false;
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + env.RESEND_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: env.FROM_EMAIL || 'onboarding@resend.dev', to, subject: subject || 'Your sign-in', text: text || '' }),
    });
    return r.ok;
  } catch (e) { return false; }
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    if (req.method !== 'POST') return json({ ok: false, error: 'POST only' }, 405);

    let body;
    try { body = await req.json(); } catch (e) { return json({ ok: false, error: 'bad json' }, 400); }
    const K = env.USERS;
    if (!K) return json({ ok: false, error: 'server not configured (no KV binding named USERS)' }, 500);
    const action = body.action;

    // ---- Public: LOGIN ----
    if (action === 'login') {
      const rec = await K.get(keyOf(body.username), 'json');
      if (!rec) return json({ ok: false, error: 'unknown' });
      const h = await sha256(rec.salt + (body.password || ''));
      if (h !== rec.hash) return json({ ok: false, error: 'password' });
      return json({ ok: true, user: stripSecret(rec) });
    }

    // ---- Public: user changes their OWN password (must supply the old one) ----
    if (action === 'setPassword') {
      const rec = await K.get(keyOf(body.username), 'json');
      if (!rec) return json({ ok: false, error: 'unknown' });
      const h = await sha256(rec.salt + (body.oldPassword || ''));
      if (h !== rec.hash) return json({ ok: false, error: 'password' });
      if (!body.newPassword || String(body.newPassword).length < 8)
        return json({ ok: false, error: 'weak' });
      rec.salt = randSalt();
      rec.hash = await sha256(rec.salt + body.newPassword);
      rec.mustChange = false;
      await K.put(keyOf(body.username), JSON.stringify(rec));
      return json({ ok: true, user: stripSecret(rec) });
    }

    // ping / health (public — no secret needed, used by the app's Test connection)
    if (action === 'ping') return json({ ok: true, service: 'signin-server', ts: new Date().toISOString() });

    // Read the shared case data — authorized by a valid LOGIN (not the admin secret), so signed-in
    // users can sync on any device (phones). Court staff/judges/admins get the full registry;
    // PARTIES/participants get ONLY the cases they are involved in (filtered here on the server so
    // other people's cases never reach their device).
    if (action === 'pullData') {
      const rec = await K.get(keyOf(body.username), 'json');
      if (!rec) return json({ ok: false, error: 'unauthorized' }, 401);
      const ok = rec.hash === await sha256(rec.salt + (body.password || ''));
      if (!ok) return json({ ok: false, error: 'unauthorized' }, 401);
      const snap = await K.get('data:registry', 'json');
      if (!snap) return json({ ok: true, data: null });
      if (rec.role !== 'participant' && rec.role !== 'judge') {
        return json({ ok: true, data: snap });   // staff / admin: full registry
      }
      // Resolve the person's name(s) used on cases.
      let myName = rec.linkedName || rec.displayName || '';
      if (rec.role === 'judge') {
        const jlist = (snap.settings && snap.settings.judges) || [];
        const m = jlist.find(j => j.email && rec.username && j.email.toLowerCase() === rec.username.toLowerCase());
        if (m) myName = m.name;
      }
      const nameSet = new Set([myName, rec.username].filter(Boolean));

      if (rec.role === 'judge') {
        // Judge: only cases where they sit on the bench.
        const onBench = (x) => (x.bench || []).some(b => b && nameSet.has(b.name));
        const myCases = (snap.cases || []).filter(onBench);
        const keep = new Set();
        myCases.forEach(x => {
          [].concat(x.appellants || [], x.respondents || [], x.intervenors || []).forEach(p => {
            if (p && p.name) keep.add(p.name);
            (p && p.lawyers || []).forEach(l => keep.add(l));
          });
          (x.bench || []).forEach(j => { if (j && j.name) keep.add(j.name); });
        });
        const myContacts = {};
        Object.keys(snap.contacts || {}).forEach(nm => { if (keep.has(nm)) myContacts[nm] = snap.contacts[nm]; });
        const safeSettings = Object.assign({}, snap.settings || {});
        delete safeSettings.backendSecret;
        return json({ ok: true, data: { cases: myCases, contacts: myContacts, settings: safeSettings, judge: true, updatedAt: snap.updatedAt } });
      }

      // Participant: only the cases they are involved in.
      const involves = (x) => {
        const pull = arr => (arr || []).flatMap(p => [p && p.name].concat((p && p.lawyers) || []));
        const all = []
          .concat(pull(x.appellants), pull(x.respondents), pull(x.intervenors))
          .concat((x.bench || []).map(j => j && j.name));
        return all.filter(Boolean).some(n => nameSet.has(n));
      };
      const myCases = (snap.cases || []).filter(involves);
      const keepNames = new Set();
      myCases.forEach(x => {
        [].concat(x.appellants || [], x.respondents || [], x.intervenors || []).forEach(p => {
          if (p && p.name) keepNames.add(p.name);
          (p && p.lawyers || []).forEach(l => keepNames.add(l));
        });
        (x.bench || []).forEach(j => { if (j && j.name) keepNames.add(j.name); });
      });
      const myContacts = {};
      Object.keys(snap.contacts || {}).forEach(n => { if (keepNames.has(n)) myContacts[n] = snap.contacts[n]; });
      return json({ ok: true, data: { cases: myCases, contacts: myContacts, participant: true, updatedAt: snap.updatedAt } });
    }

    // ---- Everything below requires the admin SECRET ----
    if (!env.SECRET || body.secret !== env.SECRET)
      return json({ ok: false, error: 'unauthorized' }, 401);

    if (action === 'register') {
      const u = body.user || {};
      if (!u.username || !u.password) return json({ ok: false, error: 'missing username or password' });
      const exists = await K.get(keyOf(u.username), 'json');
      if (exists && !body.overwrite) return json({ ok: false, error: 'exists' });
      const salt = randSalt();
      const rec = {
        username: String(u.username).trim(),
        salt,
        hash: await sha256(salt + u.password),
        role: u.role || 'participant',
        mustChange: u.mustChange !== false,
        displayName: u.displayName || '',
        linkedName: u.linkedName || '',
        designation: u.designation || '',
        chief: !!u.chief,
        email: u.email || '',
        createdAt: new Date().toISOString(),
      };
      await K.put(keyOf(u.username), JSON.stringify(rec));
      let emailed = false;
      if (u.email && body.emailBody) emailed = await sendResendEmail(env, u.email, body.emailSubject, body.emailBody);
      return json({ ok: true, emailed });
    }

    if (action === 'list') {
      const out = [];
      let cursor;
      do {
        const page = await K.list({ prefix: 'user:', cursor });
        for (const k of page.keys) {
          const r = await K.get(k.name, 'json');
          if (r) out.push(stripSecret(r));
        }
        cursor = page.list_complete ? null : page.cursor;
      } while (cursor);
      return json({ ok: true, users: out });
    }

    if (action === 'delete') {
      await K.delete(keyOf(body.username));
      return json({ ok: true });
    }

    if (action === 'resetPassword') {
      const rec = await K.get(keyOf(body.username), 'json');
      if (!rec) return json({ ok: false, error: 'unknown' });
      rec.salt = randSalt();
      rec.hash = await sha256(rec.salt + (body.newPassword || ''));
      rec.mustChange = true;
      await K.put(keyOf(body.username), JSON.stringify(rec));
      let emailed = false;
      if (rec.email && body.emailBody) emailed = await sendResendEmail(env, rec.email, body.emailSubject, body.emailBody);
      return json({ ok: true, emailed });
    }

    // ---- Shared case data (cross-device sync) ----
    // The whole registry (cases, contacts, chambers, settings, requests) is stored under one key
    // so every signed-in staff member / judge sees the same data on any device.
    if (action === 'getData') {
      const snap = await K.get('data:registry', 'json');
      return json({ ok: true, data: snap || null });
    }
    if (action === 'setData') {
      if (!body.data || typeof body.data !== 'object')
        return json({ ok: false, error: 'no data' });
      // Last-write-wins, but reject a stale write if the caller sends an older updatedAt.
      const cur = await K.get('data:registry', 'json');
      if (cur && cur.updatedAt && body.data.updatedAt && String(body.data.updatedAt) < String(cur.updatedAt) && !body.force)
        return json({ ok: false, error: 'stale', serverUpdatedAt: cur.updatedAt });
      await K.put('data:registry', JSON.stringify(body.data));
      return json({ ok: true, updatedAt: body.data.updatedAt || new Date().toISOString() });
    }

    return json({ ok: false, error: 'unknown action' }, 400);
  },
};
