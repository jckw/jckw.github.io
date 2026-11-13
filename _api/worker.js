// Storage for /journal. It only ever sees ciphertext.
//
//   GET /j/:id   -> { salt, iv, data, version }
//   PUT /j/:id   <- { salt, iv, data, version }   -> { version }
//
// :id is the passkey's credential id. Every request carries a bearer token the
// client derives from the passkey; the first PUT for an id claims it by storing
// the token's hash, and every later request has to present the same token.
// `version` is a compare-and-swap counter: a PUT based on a stale version gets
// 409, and the client merges and retries.

const ORIGINS = new Set([
  "https://www.jackw.xyz",
  "https://jackw.xyz",
  "http://localhost:8000",
]);
const MAX_JOURNALS = 3;
const MAX_DATA = 1_000_000;
const B64 = /^[A-Za-z0-9+/]*={0,2}$/;

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const cors = ORIGINS.has(origin)
      ? {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, PUT",
          "Access-Control-Allow-Headers": "Authorization, Content-Type",
          "Access-Control-Max-Age": "86400",
          Vary: "Origin",
        }
      : {};
    const reply = (status, body) =>
      new Response(body === undefined ? null : JSON.stringify(body), {
        status,
        headers: {
          ...cors,
          "Cache-Control": "no-store",
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
      });

    if (request.method === "OPTIONS") return reply(204);

    const match = new URL(request.url).pathname.match(
      /^\/j\/([A-Za-z0-9_-]{16,1400})$/
    );
    if (!match) return reply(404);
    const id = match[1];

    const token = (request.headers.get("Authorization") || "").match(
      /^Bearer ([A-Za-z0-9_-]{43})$/
    );
    if (!token) return reply(401);
    const auth = await sha256(token[1]);

    const row = await env.DB.prepare(
      "SELECT auth, salt, iv, data, version FROM journals WHERE id = ?"
    )
      .bind(id)
      .first();
    if (row && row.auth !== auth) return reply(401);

    if (request.method === "GET") {
      if (!row) return reply(404);
      const { salt, iv, data, version } = row;
      return reply(200, { salt, iv, data, version });
    }

    if (request.method !== "PUT") return reply(405);

    let body;
    try {
      body = await request.json();
    } catch {
      return reply(400);
    }
    const valid =
      body &&
      ["salt", "iv", "data"].every(
        (k) => typeof body[k] === "string" && B64.test(body[k])
      ) &&
      body.salt.length <= 64 &&
      body.iv.length <= 24 &&
      Number.isInteger(body.version);
    if (!valid) return reply(400);
    if (body.data.length > MAX_DATA) return reply(413);

    if (!row) {
      const { n } = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM journals"
      ).first();
      if (n >= MAX_JOURNALS) return reply(403);
      const created = await env.DB.prepare(
        "INSERT INTO journals (id, auth, salt, iv, data, version, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?) ON CONFLICT DO NOTHING"
      )
        .bind(id, auth, body.salt, body.iv, body.data, Date.now())
        .run();
      return created.meta.changes ? reply(200, { version: 1 }) : reply(409);
    }

    const updated = await env.DB.prepare(
      "UPDATE journals SET iv = ?, data = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?"
    )
      .bind(body.iv, body.data, Date.now(), id, body.version)
      .run();
    return updated.meta.changes
      ? reply(200, { version: body.version + 1 })
      : reply(409);
  },
};

async function sha256(text) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
