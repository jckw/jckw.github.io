# jackw.xyz

> My personal website

### Development

```bash
python3 -m http.server 8000 --cgi
```

### Journal

`/journal` is a passkey-encrypted journal. Its backend is a Cloudflare Worker
and D1 database in `_api/` (the underscore keeps it out of the Pages build).

```bash
cd _api
npx wrangler d1 execute jackw-journal --local --file schema.sql  # once
npx wrangler dev --port 8787   # the page uses this when served from localhost:8000
npx wrangler deploy
```
