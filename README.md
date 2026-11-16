# XR6 Labs HQ™ – Portal Penyelidikan & Tadbir Urus Akademik

Portal rasmi **XR6 Labs HQ™ – Research & Engineering Institute** dan **XR6 BSA – SASSI Academic Programme** yang dihoskan di **Cloudflare Workers + D1 + Static Assets** (`https://xr6labs.com`).

## Struktur Seni Bina (Single-Worker Bersepadu)

- `wrangler.toml` — Konfigurasi Worker (`src/index.js`), aset statik (`./public`), D1 (`xr6-labs-production`), dan Cron penyegerakan Zenodo (`*/30 * * * *`).
- `src/index.js` — Router API (`/api/records`, `/api/auth/*`, `/api/me`, `/api/me/profile`, `/api/admin/*`) dan pengawal keselamatan.
- `src/lib.js` — Pengesahan Cloudflare Turnstile (*fail-closed*), pengurusan sesi SHA-256, semakan ORCID iD, dan log audit.
- `src/mail.js` — Penghantaran pautan log masuk tanpa kata laluan (*Magic Link*) melalui Zoho ZeptoMail.
- `src/sync.js` — Penyegerakan automatik rekod komuniti Zenodo (`xr6labshqhub` & `xr6-bsa-sassi`) serta padanan ORCID ahli.
- `schema.sql` — Skema rasmi pangkalan data Cloudflare D1.
- `public/` — Halaman statik HTML, `robots.txt`, `sitemap.xml`, dan aset visual.

## Secrets Wajib Di Cloudflare Workers

- `TURNSTILE_SECRET_KEY` — Kunci rahsia Cloudflare Turnstile (wajib untuk `/login` dan `/register`).
- `ZEPTO_API_KEY` — Kunci API Zoho ZeptoMail untuk menghantar Magic Link.

## Pautan Rasmi

- Portal Utama: https://xr6labs.com
- Research Library: https://xr6labs.com/library
- Komuniti Zenodo HQ: https://zenodo.org/communities/xr6labshqhub
- Komuniti Zenodo SASSI: https://zenodo.org/communities/xr6-bsa-sassi
