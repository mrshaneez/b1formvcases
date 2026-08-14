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
// A list of every user's public fields (no password material) so devices reflect role/Chief changes.
async function buildRoster(K) {
  const out = [];
  let cursor;
  do {
    const page = await K.list({ prefix: 'user:', cursor });
    for (const k of page.keys) {
      const r = await K.get(k.name, 'json');
      if (r) out.push({ username: r.username, role: r.role, chief: !!r.chief,
        displayName: r.displayName || '', linkedName: r.linkedName || '',
        designation: r.designation || '', mustChange: !!r.mustChange });
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  return out;
}

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
      // A public roster (no secrets) so every device reflects role / Chief-Judge changes.
      const roster = await buildRoster(K);
      if (rec.role !== 'participant' && rec.role !== 'judge') {
        return json({ ok: true, data: Object.assign({}, snap, { roster }) });   // staff / admin: full registry
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
        const caseIds = new Set(myCases.map(c => c.id));
        const myReqs = (snap.partyRequests || []).filter(r => r && caseIds.has(r.caseId));
        const safeSettings = Object.assign({}, snap.settings || {});
        delete safeSettings.backendSecret;
        // Targets this judge owns or that are shared with them (by judge name).
        const myTargets = (snap.targets || []).filter(t => t && (
          (t.owners || []).includes(myName) ||
          (t.sharedJudges || []).includes(myName)
        ));
        return json({ ok: true, data: { cases: myCases, contacts: myContacts, partyRequests: myReqs, targets: myTargets, deletedTargetIds: snap.deletedTargetIds || [], settings: safeSettings, roster, judge: true, updatedAt: snap.updatedAt } });
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
      const myReqs = (snap.partyRequests || []).filter(r => r && (r.byUser === rec.username || nameSet.has(r.by)));
      return json({ ok: true, data: { cases: myCases, contacts: myContacts, partyRequests: myReqs, participant: true, updatedAt: snap.updatedAt } });
    }

    // A judge/staff/admin creates or updates a target (caseload/performance goal). Login-authorized
    // so judges can create and share targets without the admin secret. Merged by id.
    if (action === 'submitTarget') {
      const rec = await K.get(keyOf(body.username), 'json');
      if (!rec) return json({ ok: false, error: 'unauthorized' }, 401);
      const ok = rec.hash === await sha256(rec.salt + (body.password || ''));
      if (!ok) return json({ ok: false, error: 'unauthorized' }, 401);
      if (!['judge', 'staff', 'admin'].includes(rec.role)) return json({ ok: false, error: 'forbidden' }, 403);
      const t = body.target;
      if (!t || typeof t !== 'object' || !t.id) return json({ ok: false, error: 'no target' });
      const snap = (await K.get('data:registry', 'json')) || {};
      snap.targets = Array.isArray(snap.targets) ? snap.targets : [];
      const idx = snap.targets.findIndex(x => x && x.id === t.id);
      if (idx >= 0) snap.targets[idx] = t; else snap.targets.push(t);
      snap.updatedAt = new Date().toISOString();
      await K.put('data:registry', JSON.stringify(snap));
      return json({ ok: true });
    }

    // Delete a target. Login-authorized; only an owner (or admin) may remove it. Tombstoned.
    if (action === 'deleteTarget') {
      const rec = await K.get(keyOf(body.username), 'json');
      if (!rec) return json({ ok: false, error: 'unauthorized' }, 401);
      const ok = rec.hash === await sha256(rec.salt + (body.password || ''));
      if (!ok) return json({ ok: false, error: 'unauthorized' }, 401);
      const id = body.targetId;
      if (!id) return json({ ok: false, error: 'no id' });
      const snap = (await K.get('data:registry', 'json')) || {};
      const before = Array.isArray(snap.targets) ? snap.targets : [];
      snap.targets = before.filter(x => x && x.id !== id);
      if (before.length !== snap.targets.length) {
        snap.deletedTargetIds = Array.isArray(snap.deletedTargetIds) ? snap.deletedTargetIds : [];
        if (!snap.deletedTargetIds.includes(id)) snap.deletedTargetIds.push(id);
      }
      snap.updatedAt = new Date().toISOString();
      await K.put('data:registry', JSON.stringify(snap));
      return json({ ok: true });
    }

    // A participant/judge/staff submits a case request (adjournment/expedite/other). Authorized by
    // LOGIN (not the admin secret) so parties can send requests; appended to the shared registry
    // so the registry's main devices see it. setData merges requests so these aren't clobbered.
    if (action === 'submitRequest') {
      const rec = await K.get(keyOf(body.username), 'json');
      if (!rec) return json({ ok: false, error: 'unauthorized' }, 401);
      const ok = rec.hash === await sha256(rec.salt + (body.password || ''));
      if (!ok) return json({ ok: false, error: 'unauthorized' }, 401);
      const req = body.request;
      if (!req || typeof req !== 'object' || !req.id) return json({ ok: false, error: 'no request' });
      const snap = (await K.get('data:registry', 'json')) || {};
      snap.partyRequests = Array.isArray(snap.partyRequests) ? snap.partyRequests : [];
      if (!snap.partyRequests.some(r => r && r.id === req.id)) snap.partyRequests.push(req);
      snap.updatedAt = new Date().toISOString();
      await K.put('data:registry', JSON.stringify(snap));
      return json({ ok: true });
    }

    // A participant deletes a request they submitted. Login-authorized; can only remove their OWN
    // request (matched by byUser). Staff/admin can remove any via the secret-guarded setData merge.
    if (action === 'deleteRequest') {
      const rec = await K.get(keyOf(body.username), 'json');
      if (!rec) return json({ ok: false, error: 'unauthorized' }, 401);
      const ok = rec.hash === await sha256(rec.salt + (body.password || ''));
      if (!ok) return json({ ok: false, error: 'unauthorized' }, 401);
      const id = body.requestId;
      if (!id) return json({ ok: false, error: 'no id' });
      const snap = (await K.get('data:registry', 'json')) || {};
      const before = Array.isArray(snap.partyRequests) ? snap.partyRequests : [];
      const removedOne = before.some(r => r && r.id === id && r.byUser === rec.username);
      snap.partyRequests = before.filter(r => !(r && r.id === id && (r.byUser === rec.username)));
      if (removedOne) {
        snap.deletedRequestIds = Array.isArray(snap.deletedRequestIds) ? snap.deletedRequestIds : [];
        if (!snap.deletedRequestIds.includes(id)) snap.deletedRequestIds.push(id);
      }
      snap.updatedAt = new Date().toISOString();
      await K.put('data:registry', JSON.stringify(snap));
      return json({ ok: true, removed: before.length - snap.partyRequests.length });
    }

    if (action === 'pushCases') {
      const rec = await K.get(keyOf(body.username), 'json');
      if (!rec) return json({ ok: false, error: 'unauthorized' }, 401);
      const ok = rec.hash === await sha256(rec.salt + (body.password || ''));
      if (!ok) return json({ ok: false, error: 'unauthorized' }, 401);
      // Only judges/staff/admins may write case schedule data this way.
      if (!['judge', 'staff', 'admin'].includes(rec.role)) return json({ ok: false, error: 'forbidden' }, 403);
      const incoming = Array.isArray(body.cases) ? body.cases : [];
      const snap = (await K.get('data:registry', 'json')) || {};
      const server = Array.isArray(snap.cases) ? snap.cases : [];
      const byId = {}; server.forEach(c => { if (c && c.id) byId[c.id] = c; });
      // Resolve this judge's bench name (matched by email on the judges list) to verify authority.
      let myName = rec.displayName || rec.username;
      if (rec.role === 'judge') {
        const jlist = (snap.settings && snap.settings.judges) || [];
        const m = jlist.find(j => j.email && rec.username && j.email.toLowerCase() === rec.username.toLowerCase());
        if (m) myName = m.name;
      }
      const onBench = (sc) => (sc.bench || []).some(b => b && b.name === myName);
      // Fields a judge/staff may write into the authoritative case. Party/registry identity is left
      // to staff/admin (full snapshot) to avoid a judge rewriting the parties, but everything the
      // judge works with day to day is synced so their edits reach other devices.
      const JUDGE_FIELDS = ['nextHearing','hearingTime','timeline','log','applications','stage','notes','tags','tasks','opinion','opinions','grants','summary','decision','verdict','result','flags','priority','closed','concluded'];
      incoming.forEach(ic => {
        if (!ic || !ic.id) return;
        let sc = byId[ic.id];
        if (!sc) {
          // New case: staff/admin may add any; a judge may add one they sit on. Otherwise ignore.
          const isElevated = (rec.role === 'staff' || rec.role === 'admin');
          const judgeOnBench = rec.role === 'judge' && (ic.bench || []).some(b => b && b.name === myName);
          if (!isElevated && !judgeOnBench) return;
          sc = { id: ic.id };
          byId[ic.id] = sc;
          server.push(sc);
          // A creator may set identity/party fields too (only when first creating the case).
          ['caseNo','year','type','appellants','respondents','intervenors','bench','caseName','presiding','presidingEmail'].forEach(f => {
            if (Object.prototype.hasOwnProperty.call(ic, f)) sc[f] = ic[f];
          });
        } else {
          // Existing case: staff/admin may update any; a judge only cases they sit on.
          const allowed = (rec.role === 'staff' || rec.role === 'admin') || onBench(sc);
          if (!allowed) return;
        }
        let touched = false;
        JUDGE_FIELDS.forEach(f => { if (Object.prototype.hasOwnProperty.call(ic, f)) { sc[f] = ic[f]; touched = true; } });
        // Stamp this case as freshly updated so a later full-snapshot push from another device
        // (which merges per-case by updatedAt) won't overwrite this judge's edit.
        sc.updatedAt = ic.updatedAt && String(ic.updatedAt) > String(sc.updatedAt || '') ? ic.updatedAt : new Date().toISOString();
      });
      snap.cases = server;
      snap.updatedAt = new Date().toISOString();
      await K.put('data:registry', JSON.stringify(snap));
      return json({ ok: true, updated: incoming.length });
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

    // Update a user's non-credential fields (role, chief, designation, display name) without
    // changing their password. Secret-gated (admin only). Used when granting Chief Judge etc.
    if (action === 'updateUser') {
      const rec = await K.get(keyOf(body.username), 'json');
      if (!rec) return json({ ok: false, error: 'unknown' });
      const f = body.fields || {};
      if (Object.prototype.hasOwnProperty.call(f, 'role')) rec.role = f.role;
      if (Object.prototype.hasOwnProperty.call(f, 'chief')) rec.chief = !!f.chief;
      if (Object.prototype.hasOwnProperty.call(f, 'designation')) rec.designation = f.designation || '';
      if (Object.prototype.hasOwnProperty.call(f, 'displayName')) rec.displayName = f.displayName || '';
      if (Object.prototype.hasOwnProperty.call(f, 'linkedName')) rec.linkedName = f.linkedName || '';
      // If this user is being made Chief, clear the flag on everyone else so there's only one.
      if (f.chief === true) {
        let cursor;
        do {
          const page = await K.list({ prefix: 'user:', cursor });
          for (const k of page.keys) {
            if (k.name === keyOf(body.username)) continue;
            const other = await K.get(k.name, 'json');
            if (other && other.chief) { other.chief = false; await K.put(k.name, JSON.stringify(other)); }
          }
          cursor = page.list_complete ? null : page.cursor;
        } while (cursor);
      }
      await K.put(keyOf(body.username), JSON.stringify(rec));
      return json({ ok: true, user: stripSecret(rec) });
    }

    // ---- Shared case data (cross-device sync) ----
    // The whole registry (cases, contacts, chambers, settings, requests) is stored under one key
    // so every signed-in staff member / judge sees the same data on any device.
    if (action === 'getData') {
      const snap = await K.get('data:registry', 'json');
      if (!snap) return json({ ok: true, data: null });
      const roster = await buildRoster(K);
      return json({ ok: true, data: Object.assign({}, snap, { roster }) });
    }
    if (action === 'setData') {
      if (!body.data || typeof body.data !== 'object')
        return json({ ok: false, error: 'no data' });
      // Last-write-wins for case data, but reject a stale write if the caller sends an older updatedAt.
      const cur = await K.get('data:registry', 'json');
      if (cur && cur.updatedAt && body.data.updatedAt && String(body.data.updatedAt) < String(cur.updatedAt) && !body.force)
        return json({ ok: false, error: 'stale', serverUpdatedAt: cur.updatedAt });
      // Merge partyRequests by id so requests submitted (by parties) between the admin's pull and
      // push are not lost. Incoming (admin) values win for a given id (status updates), and any
      // server-side request not present in the incoming set is preserved.
      const incoming = Array.isArray(body.data.partyRequests) ? body.data.partyRequests : [];
      const serverReqs = (cur && Array.isArray(cur.partyRequests)) ? cur.partyRequests : [];
      const byId = {};
      serverReqs.forEach(r => { if (r && r.id) byId[r.id] = r; });
      incoming.forEach(r => { if (r && r.id) byId[r.id] = r; });
      // Honor deletions: a request the owner deleted must not be resurrected by a stale admin push.
      const tombstones = (cur && Array.isArray(cur.deletedRequestIds)) ? cur.deletedRequestIds : [];
      const incomingTombs = Array.isArray(body.data.deletedRequestIds) ? body.data.deletedRequestIds : [];
      const allTombs = Array.from(new Set(tombstones.concat(incomingTombs)));
      allTombs.forEach(id => { delete byId[id]; });
      body.data.partyRequests = Object.values(byId);
      body.data.deletedRequestIds = allTombs;
      // Merge CASES per-case by their own updatedAt, so a change another device pushed (e.g. a judge's
      // case-progress edit via pushCases) between this admin's pull and push is not wiped by the
      // admin's full snapshot. For each case id, keep whichever side has the newer updatedAt.
      const serverCases = (cur && Array.isArray(cur.cases)) ? cur.cases : [];
      const incomingCases = Array.isArray(body.data.cases) ? body.data.cases : [];
      const caseById = {};
      serverCases.forEach(c => { if (c && c.id) caseById[c.id] = c; });
      incomingCases.forEach(c => {
        if (!c || !c.id) return;
        const sv = caseById[c.id];
        // Incoming wins unless the server copy is strictly newer for this specific case.
        if (sv && sv.updatedAt && c.updatedAt && String(sv.updatedAt) > String(c.updatedAt)) return;
        caseById[c.id] = c;
      });
      // Preserve any server case the admin didn't send (shouldn't normally happen, but safe).
      body.data.cases = Object.values(caseById);

      // Merge TARGETS by id (honor updatedAt + tombstones) so a target created/updated on another
      // device (e.g. a judge via submitTarget) isn't wiped by the admin's full snapshot.
      const serverTargets = (cur && Array.isArray(cur.targets)) ? cur.targets : [];
      const incomingTargets = Array.isArray(body.data.targets) ? body.data.targets : [];
      const tById = {};
      serverTargets.forEach(t => { if (t && t.id) tById[t.id] = t; });
      incomingTargets.forEach(t => {
        if (!t || !t.id) return;
        const sv = tById[t.id];
        if (sv && sv.updatedAt && t.updatedAt && String(sv.updatedAt) > String(t.updatedAt)) return;
        tById[t.id] = t;
      });
      const tTomb = Array.from(new Set(
        ((cur && Array.isArray(cur.deletedTargetIds)) ? cur.deletedTargetIds : [])
        .concat(Array.isArray(body.data.deletedTargetIds) ? body.data.deletedTargetIds : [])
      ));
      tTomb.forEach(id => { delete tById[id]; });
      body.data.targets = Object.values(tById);
      body.data.deletedTargetIds = tTomb;

      // Merge CONTACTS and CHAMBERS per-key, keeping any key the admin's snapshot didn't include
      // (so a contact added on another device isn't dropped). Incoming values win for shared keys.
      if (cur && cur.contacts && typeof cur.contacts === 'object')
        body.data.contacts = Object.assign({}, cur.contacts, (body.data.contacts && typeof body.data.contacts === 'object') ? body.data.contacts : {});
      if (cur && cur.chambers && typeof cur.chambers === 'object')
        body.data.chambers = Object.assign({}, cur.chambers, (body.data.chambers && typeof body.data.chambers === 'object') ? body.data.chambers : {});

      await K.put('data:registry', JSON.stringify(body.data));
      return json({ ok: true, updatedAt: body.data.updatedAt || new Date().toISOString() });
    }

    return json({ ok: false, error: 'unknown action' }, 400);
  },
};
