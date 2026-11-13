// A tiny passkey-encrypted journal.
//
// The passkey's PRF extension yields 32 secret bytes that only that passkey
// can produce. From them HKDF derives two things, both kept in memory only:
//   - a non-extractable AES-GCM key that encrypts the entries, and
//   - a bearer token that proves to the server we hold the passkey.
// The server (see /_api) and localStorage only ever hold ciphertext:
// { cred, salt, iv, data, version }. localStorage is the offline copy.
//
// Decrypted, the journal is { "YYYY-MM-DD": { t: text, m: modifiedMs } }.
// Two devices merge by taking the newer `m` per day; an emptied day stays
// behind as t: "" so the deletion wins on the other device too.
(() => {
  "use strict";

  const API =
    location.hostname === "localhost"
      ? "http://localhost:8787"
      : "https://jackw-journal.jackweatherilt.workers.dev";
  const STORE = "journal";
  const SAVE_DELAY = 400;
  const DAY = /^\d{4}-\d{2}-\d{2}$/;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const PRF_INPUT = enc.encode("jackw.xyz journal v1");
  const KEY_INFO = enc.encode("journal aes-gcm v1");
  const AUTH_INFO = enc.encode("journal auth v1");
  const RP_ID = location.hostname.replace(/^www\./, "");

  const $ = (id) => document.getElementById(id);
  const views = ["unsupported", "empty", "locked", "open"];

  let record = loadRecord(); // ciphertext, as stored locally
  let key = null; // set while unlocked
  let token = null;
  let entries = {};
  let dirty = false; // local changes the server hasn't accepted yet
  let saveTimer = null;
  let saving = Promise.resolve();

  // --- bytes ---------------------------------------------------------------

  function b64(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s);
  }

  function unb64(s) {
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  }

  const urlSafe = (s) =>
    s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const random = (n) => crypto.getRandomValues(new Uint8Array(n));

  // Password-manager extensions replace navigator.credentials and don't always
  // hand back the ArrayBuffers the browser would: strings, plain arrays and
  // { 0: 1, 1: 2, … } objects all turn up. Normalise to a Uint8Array, and
  // refuse anything that isn't `size` bytes rather than derive a key from junk.
  function bytes(v, what, size) {
    let out = null;
    try {
      if (typeof v === "string") {
        out = unb64(v.replace(/-/g, "+").replace(/_/g, "/"));
      } else if (ArrayBuffer.isView(v)) {
        out = new Uint8Array(v.buffer, v.byteOffset, v.byteLength).slice();
      } else if (Object.prototype.toString.call(v) === "[object ArrayBuffer]") {
        out = new Uint8Array(v).slice();
      } else if (v && typeof v === "object") {
        const list = typeof v.length === "number" ? Array.from(v) : Object.values(v);
        if (list.every((n) => Number.isInteger(n) && n >= 0 && n < 256)) {
          out = Uint8Array.from(list);
        }
      }
    } catch {}
    if (!out || !out.length || (size && out.length !== size)) {
      const shape =
        v && typeof v === "object"
          ? `${Object.prototype.toString.call(v)} with ${Object.keys(v).length} keys`
          : typeof v;
      const err = new Error(`the passkey provider returned an unusable ${what} (${shape})`);
      err.name = "PasskeyError";
      throw err;
    }
    return out;
  }

  // --- local copy ----------------------------------------------------------

  function loadRecord() {
    try {
      const r = JSON.parse(localStorage.getItem(STORE));
      const fields = ["cred", "salt", "iv", "data"];
      if (!r || !fields.every((k) => typeof r[k] === "string")) return null;
      fields.forEach((k) => atob(r[k]));
      if (!r.cred || !r.salt) return null;
      return {
        cred: r.cred,
        salt: r.salt,
        iv: r.iv,
        data: r.data,
        version: Number.isInteger(r.version) ? r.version : 0,
      };
    } catch {
      return null;
    }
  }

  function store() {
    localStorage.setItem(STORE, JSON.stringify(record));
  }

  // --- passkey -------------------------------------------------------------

  async function createPasskey() {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: random(32),
        rp: { name: "Journal", id: RP_ID },
        user: { id: random(16), name: "journal", displayName: "Journal" },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "required",
        },
        extensions: { prf: { eval: { first: PRF_INPUT } } },
      },
    });
    const prf = cred.getClientExtensionResults().prf;
    if (!prf || !(prf.enabled || prf.results)) throw new Error("no-prf");
    // Some authenticators only hand over PRF output when signing in, not at
    // creation. Then there's no secret yet, and the first unlock supplies it.
    const first = prf.results && prf.results.first;
    return {
      id: bytes(cred.rawId, "credential id"),
      secret: first ? bytes(first, "secret", 32) : null,
    };
  }

  // With no credId the browser offers whichever journal passkeys it has,
  // which is how a second device finds the journal.
  async function getPasskey(credId) {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: random(32),
        rpId: RP_ID,
        allowCredentials: credId ? [{ type: "public-key", id: credId }] : [],
        userVerification: "required",
        extensions: { prf: { eval: { first: PRF_INPUT } } },
      },
    });
    const prf = assertion.getClientExtensionResults().prf;
    if (!prf || !prf.results || !prf.results.first) throw new Error("no-prf");
    return {
      id: bytes(assertion.rawId, "credential id"),
      secret: bytes(prf.results.first, "secret", 32),
    };
  }

  const hkdf = (secret) =>
    crypto.subtle.importKey("raw", secret, "HKDF", false, [
      "deriveKey",
      "deriveBits",
    ]);

  async function deriveKey(secret, salt) {
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: KEY_INFO },
      await hkdf(secret),
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function deriveToken(secret) {
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: AUTH_INFO },
      await hkdf(secret),
      256
    );
    return urlSafe(b64(bits));
  }

  // --- encrypt / decrypt ---------------------------------------------------

  async function seal() {
    const iv = random(12);
    const data = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      enc.encode(JSON.stringify(entries))
    );
    record.iv = b64(iv);
    record.data = b64(data);
    store();
  }

  async function unseal(r, k) {
    if (!r.data) return {}; // created, never yet unlocked
    let parsed;
    try {
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: unb64(r.iv) },
        k,
        unb64(r.data)
      );
      parsed = JSON.parse(dec.decode(plain));
    } catch {
      throw new Error("wrong-key");
    }
    const out = {};
    for (const [day, e] of Object.entries(parsed || {})) {
      if (DAY.test(day) && e && typeof e.t === "string" && Number.isFinite(e.m)) {
        out[day] = { t: e.t, m: e.m };
      }
    }
    return out;
  }

  function merge(theirs) {
    for (const [day, e] of Object.entries(theirs)) {
      if (!entries[day] || e.m > entries[day].m) entries[day] = e;
    }
  }

  function same(a, b) {
    const days = Object.keys(a);
    return (
      days.length === Object.keys(b).length &&
      days.every((d) => b[d] && a[d].t === b[d].t && a[d].m === b[d].m)
    );
  }

  // --- server --------------------------------------------------------------

  async function api(method, body) {
    try {
      return await fetch(`${API}/j/${urlSafe(record.cred)}`, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch {
      throw new Error("offline");
    }
  }

  async function pull() {
    const res = await api("GET");
    if (res.status === 404) return null;
    if (!res.ok) throw new Error("http-" + res.status);
    return res.json();
  }

  // Fold a newer server copy into what we have.
  async function absorb(remote) {
    const theirs = await unseal(remote, key);
    const before = JSON.stringify(entries);
    merge(theirs);
    record.version = remote.version;
    dirty = dirty || !same(entries, theirs);
    await seal();
    if (JSON.stringify(entries) !== before) renderEntries();
  }

  async function push() {
    for (let attempt = 0; attempt < 4; attempt++) {
      const { salt, iv, data, version } = record;
      const res = await api("PUT", { salt, iv, data, version });
      if (res.ok) {
        record.version = (await res.json()).version;
        store();
        dirty = false;
        return;
      }
      if (res.status !== 409) throw new Error("http-" + res.status);
      // Another device got there first: merge its copy and go again.
      const remote = await pull();
      if (remote) await absorb(remote);
      else record.version = 0;
    }
    throw new Error("http-409");
  }

  function unsynced(err) {
    if (err.message !== "offline") console.error(err);
    setStatus(
      err.message === "offline"
        ? "Saved on this device — offline"
        : err.message === "http-403"
        ? "Saved on this device only — the server isn't taking new journals"
        : "Saved on this device — sync failed"
    );
  }

  function scheduleSave() {
    setStatus("Saving…");
    clearTimeout(saveTimer);
    saveTimer = setTimeout(flush, SAVE_DELAY);
  }

  // Encrypt to localStorage, then send to the server. Runs are queued so two
  // never overlap.
  function flush() {
    clearTimeout(saveTimer);
    saveTimer = null;
    saving = saving.then(async () => {
      if (!key) return;
      try {
        await seal();
      } catch (err) {
        console.error(err);
        return setStatus("Couldn't save — storage may be full");
      }
      try {
        await push();
        if (!saveTimer) setStatus("Saved");
      } catch (err) {
        unsynced(err);
      }
    });
    return saving;
  }

  // Pick up changes made elsewhere, and send anything still waiting.
  function refresh() {
    saving = saving.then(async () => {
      if (!key) return;
      try {
        const remote = await pull();
        if (!remote) dirty = true;
        else if (remote.version !== record.version) await absorb(remote);
        if (dirty) {
          await push();
          if (!saveTimer) setStatus("Saved");
        }
      } catch (err) {
        if (dirty) unsynced(err);
      }
    });
    return saving;
  }

  // --- actions -------------------------------------------------------------

  async function create() {
    const { id, secret } = await createPasskey();
    const salt = random(32);
    record = { cred: b64(id), salt: b64(salt), iv: "", data: "", version: 0 };
    store();
    if (!secret) {
      render();
      return setStatus("Passkey created — unlock to start writing");
    }
    key = await deriveKey(secret, salt);
    token = await deriveToken(secret);
    entries = {};
    dirty = true;
    await seal();
    askToPersist();
    render();
    flush();
  }

  async function unlock() {
    const local = record;
    try {
      const { id, secret } = await getPasskey(local && unb64(local.cred));
      token = await deriveToken(secret);
      record = { cred: b64(id), salt: "", iv: "", data: "", version: 0 };

      let remote = null;
      let reachable = true;
      try {
        remote = await pull();
      } catch (err) {
        if (err.message === "http-401") throw new Error("wrong-key");
        reachable = false;
      }
      // A passkey with no journal anywhere (say, creation was interrupted)
      // simply starts an empty one.
      if (!remote && !local && !reachable) throw new Error("offline");

      record.salt = (remote || local || { salt: b64(random(32)) }).salt;
      const k = await deriveKey(secret, unb64(record.salt));
      const mine = local ? await unseal(local, k) : {};
      const theirs = remote ? await unseal(remote, k) : null;

      key = k;
      entries = mine;
      if (theirs) merge(theirs);
      record.version = remote ? remote.version : reachable ? 0 : local.version;
      dirty = !theirs || !same(entries, theirs);
      await seal();
      askToPersist();
      render();
      if (!reachable) setStatus("Offline — changes will sync later");
      else if (dirty) flush();
    } catch (err) {
      forget();
      record = local;
      throw err;
    }
  }

  async function lock() {
    if (saveTimer) flush();
    await saving;
    forget();
    render();
  }

  function forget() {
    clearTimeout(saveTimer);
    saveTimer = null;
    key = null;
    token = null;
    entries = {};
    dirty = false;
    $("entries").replaceChildren();
  }

  // Ask the browser not to evict the offline copy under pressure. Best effort.
  function askToPersist() {
    if (navigator.storage && navigator.storage.persist) {
      navigator.storage.persist().catch(() => {});
    }
  }

  // --- view ----------------------------------------------------------------

  const pad = (n) => String(n).padStart(2, "0");

  function dayKey(d = new Date()) {
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  }

  function dayLabel(k) {
    const [y, m, d] = k.split("-").map(Number);
    return new Date(y, m - 1, d).toLocaleDateString(undefined, {
      weekday: "long",
      day: "numeric",
      month: "long",
      year: "numeric",
    });
  }

  function setStatus(text) {
    $("status").textContent = text;
  }

  function fit(textarea) {
    textarea.style.height = "auto";
    textarea.style.height = textarea.scrollHeight + "px";
  }

  // Rebuilds the list. If the user is mid-sentence when a merge lands, their
  // focus and cursor are put back where they were.
  function renderEntries(focusToday) {
    const root = $("entries");
    const active = document.activeElement;
    const held =
      active && root.contains(active)
        ? { day: active.dataset.day, at: active.selectionStart }
        : null;

    const today = dayKey();
    const days = Object.keys(entries)
      .filter((d) => d !== today && entries[d].t)
      .sort()
      .reverse();
    days.unshift(today);

    const nodes = days.map((day) => {
      const section = document.createElement("section");
      section.className = "journal-entry";

      const heading = document.createElement("h2");
      heading.textContent = day === today ? "Today" : dayLabel(day);

      const textarea = document.createElement("textarea");
      textarea.rows = 1;
      textarea.spellcheck = true;
      textarea.dataset.day = day;
      textarea.value = entries[day] ? entries[day].t : "";
      textarea.setAttribute("aria-label", dayLabel(day));
      if (day === today) textarea.placeholder = "Write something…";
      textarea.addEventListener("input", () => {
        entries[day] = { t: textarea.value, m: Date.now() };
        dirty = true;
        fit(textarea);
        scheduleSave();
      });

      section.append(heading, textarea);
      return section;
    });

    root.replaceChildren(...nodes);
    const areas = [...root.querySelectorAll("textarea")];
    areas.forEach(fit);

    const target = held
      ? areas.find((a) => a.dataset.day === held.day)
      : focusToday
      ? areas[0]
      : null;
    if (target) {
      target.focus();
      if (held) target.setSelectionRange(held.at, held.at);
    }
  }

  function render() {
    const supported =
      window.isSecureContext && window.PublicKeyCredential && crypto.subtle;
    const view = !supported
      ? "unsupported"
      : key
      ? "open"
      : record
      ? "locked"
      : "empty";

    views.forEach((v) => ($("view-" + v).hidden = v !== view));
    $("lock").hidden = view !== "open";
    setStatus("");

    if (view === "locked") $("cipher").textContent = record.data.slice(0, 600);
    if (view === "open") renderEntries(true);
  }

  function explain(err) {
    const known = {
      "no-prf": "This passkey provider can't derive encryption keys — try another",
      "wrong-key": "That passkey doesn't open this journal",
      offline: "Can't reach the server",
    };
    if (err && known[err.message]) return known[err.message];
    if (err && (err.name === "NotAllowedError" || err.name === "AbortError")) {
      return "Cancelled";
    }
    console.error(err);
    const detail = err && [err.name, err.message].filter(Boolean).join(": ");
    return "Something went wrong" + (detail ? ` (${detail.slice(0, 200)})` : "");
  }

  function action(button, fn) {
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await fn();
      } catch (err) {
        setStatus(explain(err));
      } finally {
        button.disabled = false;
      }
    });
  }

  action($("create"), create);
  action($("open-existing"), unlock);
  action($("unlock"), unlock);
  action($("lock"), lock);

  document.addEventListener("visibilitychange", () => {
    if (!key) return;
    // Leaving: don't let typed text sit in the debounce. Returning: catch up.
    if (document.hidden) saveTimer && flush();
    else refresh();
  });

  window.addEventListener("online", () => key && refresh());

  // Another tab changed the local copy: lock rather than overwrite its work.
  window.addEventListener("storage", (e) => {
    if (e.key !== STORE && e.key !== null) return;
    forget();
    record = loadRecord();
    render();
  });

  render();
})();
