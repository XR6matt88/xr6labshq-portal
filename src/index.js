import {
  json,
  sha256Hex,
  generateToken,
  buildSessionCookie,
  clearSessionCookie,
  getCurrentMember,
  deleteCurrentSession,
  verifyTurnstile,
  normaliseOrcid,
  isValidOrcid,
  logAudit
} from './lib.js';
import { sendMagicLinkEmail } from './mail.js';
import { syncAllCommunities } from './sync.js';

const ALLOWED_STATUSES = new Set(['pending', 'active', 'suspended']);
const ALLOWED_ROLES = new Set(['member', 'secondary_admin', 'admin']);
const MAX_ANNOUNCEMENT_MEDIA_BYTES = 25 * 1024 * 1024;

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(syncAllCommunities(env));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      // 1. API Awam: Katalog Rekod Zenodo (Research Library)
      if (path === '/api/records' && method === 'GET') {
        const q = (url.searchParams.get('q') || '').trim();
        const community = (url.searchParams.get('community') || '').trim();

        let query = `SELECT * FROM zenodo_records`;
        const params = [];
        const conditions = [];

        if (community) {
          conditions.push(`community_slug = ?`);
          params.push(community);
        }
        if (q) {
          conditions.push(`(title LIKE ? OR abstract LIKE ? OR authors_json LIKE ?)`);
          const like = `%${q}%`;
          params.push(like, like, like);
        }

        if (conditions.length > 0) {
          query += ` WHERE ` + conditions.join(' AND ');
        }
        query += ` ORDER BY publication_date DESC, synced_at DESC LIMIT 100`;

        const { results } = await env.DB.prepare(query).bind(...params).all();
        return json({ ok: true, records: results || [] });
      }

      // Pengumuman & aktiviti yang aktif dipaparkan kepada semua pelawat.
      if (path === '/api/announcements' && method === 'GET') {
        const { results } = await env.DB.prepare(`
          SELECT id, title, category, description, media_type, media_key,
                 media_filename, media_mime, activity_date, created_at
          FROM announcements
          WHERE is_active = 1
          ORDER BY activity_date DESC, created_at DESC
        `).all();
        return json({ ok: true, announcements: results || [] });
      }

      // Strim media awam daripada R2. Kekunci dihadkan kepada objek pengumuman.
      if (path.startsWith('/api/media/') && method === 'GET') {
        let key;
        try {
          key = decodeURIComponent(path.slice('/api/media/'.length));
        } catch {
          return new Response('Media tidak dijumpai', { status: 404 });
        }

        if (!env.MEDIA_BUCKET || !key || !key.startsWith('announcements/') || key.includes('..')) {
          return new Response('Media tidak dijumpai', { status: 404 });
        }

        const object = await env.MEDIA_BUCKET.get(key);
        if (!object) return new Response('Fail tidak wujud', { status: 404 });

        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set('ETag', object.httpEtag);
        headers.set('X-Content-Type-Options', 'nosniff');
        headers.set('Cache-Control', 'public, max-age=3600');
        return new Response(object.body, { headers });
      }

      // Muat naik pengumuman dan lampiran: admin atau secondary_admin sahaja.
      if (path === '/api/admin/announcements' && method === 'POST') {
        const member = await getCurrentMember(request, env);
        if (!member || (member.role !== 'admin' && member.role !== 'secondary_admin')) {
          return json({ ok: false, error: 'Akses ditolak: Hanya untuk Admin dan Second Admin.' }, 403);
        }

        let formData;
        try {
          formData = await request.formData();
        } catch {
          return json({ ok: false, error: 'Format borang tidak sah.' }, 400);
        }

        const title = String(formData.get('title') || '').trim().slice(0, 200);
        const category = String(formData.get('category') || 'Aktiviti').trim().slice(0, 80);
        const description = String(formData.get('description') || '').trim().slice(0, 10000);
        const activityDate = String(formData.get('activity_date') || new Date().toISOString().slice(0, 10)).trim();
        const file = formData.get('media_file');

        if (!title) {
          return json({ ok: false, error: 'Tajuk pengumuman wajib diisi.' }, 400);
        }
        if (!/^\d{4}-\d{2}-\d{2}$/.test(activityDate) || Number.isNaN(Date.parse(`${activityDate}T00:00:00Z`))) {
          return json({ ok: false, error: 'Tarikh aktiviti tidak sah.' }, 400);
        }

        const id = crypto.randomUUID();
        let mediaType = 'none';
        let mediaKey = null;
        let mediaFilename = null;
        let mediaMime = null;

        if (file && typeof file === 'object' && typeof file.arrayBuffer === 'function' && file.size > 0) {
          if (!env.MEDIA_BUCKET) {
            return json({ ok: false, error: 'Storan MEDIA_BUCKET belum disambungkan di Cloudflare.' }, 500);
          }
          if (file.size > MAX_ANNOUNCEMENT_MEDIA_BYTES) {
            return json({ ok: false, error: 'Saiz fail maksimum ialah 25 MB.' }, 413);
          }

          mediaMime = String(file.type || 'application/octet-stream').slice(0, 160);
          mediaFilename = String(file.name || 'lampiran').slice(0, 255);
          if (mediaMime.startsWith('image/')) mediaType = 'image';
          else if (mediaMime.startsWith('audio/')) mediaType = 'audio';
          else if (mediaMime.startsWith('video/')) mediaType = 'video';
          else mediaType = 'document';

          const safeName = mediaFilename.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 180) || 'lampiran';
          mediaKey = `announcements/${id}-${safeName}`;
          await env.MEDIA_BUCKET.put(mediaKey, await file.arrayBuffer(), {
            httpMetadata: { contentType: mediaMime }
          });
        }

        await env.DB.prepare(`
          INSERT INTO announcements (
            id, title, category, description, media_type, media_key,
            media_filename, media_mime, activity_date, created_by
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          id, title, category, description, mediaType, mediaKey,
          mediaFilename, mediaMime, activityDate, member.email
        ).run();

        return json({ ok: true, id });
      }

      // Padam pengumuman serta lampiran R2: admin atau secondary_admin sahaja.
      if (path.startsWith('/api/admin/announcements/') && method === 'DELETE') {
        const member = await getCurrentMember(request, env);
        if (!member || (member.role !== 'admin' && member.role !== 'secondary_admin')) {
          return json({ ok: false, error: 'Akses ditolak.' }, 403);
        }

        let id;
        try {
          id = decodeURIComponent(path.slice('/api/admin/announcements/'.length)).trim();
        } catch {
          return json({ ok: false, error: 'ID pengumuman tidak sah.' }, 400);
        }
        if (!id || id.includes('/')) return json({ ok: false, error: 'ID pengumuman tidak sah.' }, 400);

        const existing = await env.DB.prepare(`SELECT media_key FROM announcements WHERE id = ?`).bind(id).first();
        if (existing?.media_key && env.MEDIA_BUCKET) {
          await env.MEDIA_BUCKET.delete(existing.media_key);
        }
        await env.DB.prepare(`DELETE FROM announcements WHERE id = ?`).bind(id).run();
        return json({ ok: true });
      }

      // 2. API Auth: Minta Pautan Log Masuk / Pendaftaran (Magic Link)
      if (path === '/api/auth/request-link' && method === 'POST') {
        let body;
        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: 'Format permintaan JSON tidak sah.' }, 400);
        }

        const email = String(body.email || '').trim().toLowerCase();
        const turnstileToken = String(body.turnstileToken || '');
        const displayName = String(body.displayName || '').trim().slice(0, 120);
        const institution = String(body.institution || '').trim().slice(0, 160);
        const orcidId = normaliseOrcid(body.orcidId || '');

        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json({ ok: false, error: 'Alamat e-mel tidak sah.' }, 400);
        }

        if (orcidId && !isValidOrcid(orcidId)) {
          return json({ ok: false, error: 'Format ORCID iD tidak sah. Contoh sah: 0000-0002-1825-0097.' }, 400);
        }

        const ip = request.headers.get('CF-Connecting-IP') || '';
        const humanOk = await verifyTurnstile(turnstileToken, ip, env);
        if (!humanOk) {
          return json({ ok: false, error: 'Pengesahan keselamatan Turnstile gagal.' }, 403);
        }

        // Had kadar permintaan (Rate Limit): Cooldown 60 saat & maks 3 pautan aktif per e-mel dalam 15 minit
        const cooldownHit = await env.DB.prepare(`
          SELECT id FROM auth_tokens
          WHERE email = ? AND datetime(expires_at) > datetime('now', '+14 minutes')
          LIMIT 1
        `).bind(email).first();

        if (cooldownHit) {
          return json({ ok: false, error: 'Sila tunggu sekurang-kurangnya 60 saat sebelum meminta pautan baharu.' }, 429);
        }

        const activeCountRow = await env.DB.prepare(`
          SELECT COUNT(*) AS total FROM auth_tokens
          WHERE email = ? AND datetime(expires_at) > CURRENT_TIMESTAMP
        `).bind(email).first();

        if ((activeCountRow?.total || 0) >= 3) {
          return json({ ok: false, error: 'Terlalu banyak permintaan pautan pengesahan. Sila cuba lagi selepas 15 minit.' }, 429);
        }

        // Had kadar permintaan per IP menggunakan audit_logs (maks 10 permintaan / 15 minit)
        const ipHash = await sha256Hex(ip || 'unknown');
        try {
          const ipCountRow = await env.DB.prepare(`
            SELECT COUNT(*) AS total FROM audit_logs
            WHERE action = 'REQUEST_MAGIC_LINK'
              AND target_id = ?
              AND datetime(created_at) > datetime('now', '-15 minutes')
          `).bind(ipHash).first();

          if ((ipCountRow?.total || 0) >= 10) {
            return json({ ok: false, error: 'Had permintaan daripada alamat IP anda telah dicapai. Sila cuba sebentar lagi.' }, 429);
          }
        } catch {
          // Abaikan jika jadual audit_logs belum mempunyai lajur created_at
        }

        // Jika datang daripada borang pendaftaran (/register), simpan maklumat asas ahli baharu yang belum disahkan
        if (displayName || institution || orcidId) {
          const existing = await env.DB.prepare(`
            SELECT id, email_verified, status FROM members WHERE email = ?
          `).bind(email).first();

          if (!existing) {
            const fallbackName = displayName || email.split('@')[0];
            await env.DB.prepare(`
              INSERT INTO members (id, email, email_verified, display_name, institution, orcid_id, role, status)
              VALUES (?, ?, 0, ?, ?, ?, 'member', 'pending')
            `).bind(
              crypto.randomUUID(),
              email,
              fallbackName,
              institution || null,
              orcidId || null
            ).run();
          } else if (!existing.email_verified && existing.status === 'pending') {
            await env.DB.prepare(`
              UPDATE members
              SET display_name = COALESCE(NULLIF(?, ''), display_name),
                  institution = COALESCE(NULLIF(?, ''), institution),
                  orcid_id = COALESCE(NULLIF(?, ''), orcid_id),
                  updated_at = CURRENT_TIMESTAMP
              WHERE id = ?
            `).bind(displayName, institution, orcidId, existing.id).run();
          }
        }

        const rawToken = generateToken(32);
        const tokenHash = await sha256Hex(rawToken);
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

        await env.DB.prepare(`
          INSERT INTO auth_tokens (id, email, token_hash, purpose, expires_at)
          VALUES (?, ?, ?, 'login', ?)
        `).bind(crypto.randomUUID(), email, tokenHash, expiresAt).run();

        const magicUrl = `${url.origin}/api/auth/verify?token=${rawToken}`;
        await sendMagicLinkEmail(env, email, magicUrl);
        await logAudit(env, null, 'REQUEST_MAGIC_LINK', 'ip', ipHash, { email });

        return json({ ok: true, message: 'Pautan pengesahan telah dihantar ke e-mel anda.' });
      }

      // 3. API Auth: Sahkan Pautan Log Masuk Secara Atomik (Magic Link Callback)
      if (path === '/api/auth/verify' && method === 'GET') {
        const rawToken = url.searchParams.get('token') || '';
        if (!rawToken) return Response.redirect(`${url.origin}/login?error=missing_token`, 302);

        const tokenHash = await sha256Hex(rawToken);
        const tokenRow = await env.DB.prepare(`
          UPDATE auth_tokens
          SET used_at = CURRENT_TIMESTAMP
          WHERE token_hash = ?
            AND used_at IS NULL
            AND datetime(expires_at) > CURRENT_TIMESTAMP
          RETURNING id, email, purpose
        `).bind(tokenHash).first();

        if (!tokenRow) {
          return Response.redirect(`${url.origin}/login?error=invalid_or_expired`, 302);
        }

        let member = await env.DB.prepare(`SELECT * FROM members WHERE email = ?`)
          .bind(tokenRow.email).first();

        if (member && member.status === 'suspended') {
          return Response.redirect(`${url.origin}/login?error=account_suspended`, 302);
        }

        if (!member) {
          const newId = crypto.randomUUID();
          const defaultName = tokenRow.email.split('@')[0];
          await env.DB.prepare(`
            INSERT INTO members (id, email, email_verified, display_name, role, status)
            VALUES (?, ?, 1, ?, 'member', 'pending')
          `).bind(newId, tokenRow.email, defaultName).run();
          member = await env.DB.prepare(`SELECT * FROM members WHERE id = ?`).bind(newId).first();
        } else if (!member.email_verified) {
          await env.DB.prepare(`UPDATE members SET email_verified = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
            .bind(member.id).run();
        }

        const sessionRaw = generateToken(32);
        const sessionHash = await sha256Hex(sessionRaw);
        const sessionExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

        await env.DB.prepare(`
          INSERT INTO sessions (id, member_id, token_hash, user_agent, expires_at)
          VALUES (?, ?, ?, ?, ?)
        `).bind(
          crypto.randomUUID(),
          member.id,
          sessionHash,
          request.headers.get('User-Agent') || '',
          sessionExpires
        ).run();

        const dest = (member.role === 'admin' || member.role === 'secondary_admin')
          ? `${url.origin}/admin`
          : `${url.origin}/dashboard`;

        return new Response(null, {
          status: 302,
          headers: {
            'Location': dest,
            'Set-Cookie': buildSessionCookie(sessionRaw)
          }
        });
      }

      // 4. API Auth: Log Keluar (Padam Sesi D1 + Cookie)
      if (path === '/api/auth/logout' && method === 'POST') {
        await deleteCurrentSession(request, env);
        return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie() });
      }

      // 5. API Profil Ahli Semasa (/api/me)
      if (path === '/api/me' && method === 'GET') {
        const member = await getCurrentMember(request, env);
        if (!member) return json({ ok: false, error: 'Tidak log masuk.' }, 401);

        const { results: pubs } = await env.DB.prepare(`
          SELECT zr.*, mp.match_method, mp.verified_by_admin
          FROM member_publications mp
          JOIN zenodo_records zr ON mp.zenodo_id = zr.zenodo_id
          WHERE mp.member_id = ?
          ORDER BY zr.publication_date DESC
        `).bind(member.id).all();

        return json({ ok: true, member, publications: pubs || [] });
      }

      // 5b. API Kemas Kini Profil Ahli (/api/me/profile)
      if (path === '/api/me/profile' && method === 'POST') {
        const member = await getCurrentMember(request, env);
        if (!member) return json({ ok: false, error: 'Sesi tamat. Sila log masuk semula.' }, 401);

        let body;
        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: 'Format JSON tidak sah.' }, 400);
        }

        const displayName = String(body.displayName || '').trim().slice(0, 120);
        const institution = String(body.institution || '').trim().slice(0, 160);
        const researchField = String(body.researchField || '').trim().slice(0, 160);
        const orcidId = normaliseOrcid(body.orcidId || '');

        if (!displayName) {
          return json({ ok: false, error: 'Nama paparan diperlukan.' }, 400);
        }
        if (orcidId && !isValidOrcid(orcidId)) {
          return json({ ok: false, error: 'Format ORCID iD tidak sah. Gunakan format seperti 0000-0002-1825-0097.' }, 400);
        }

        const orcidChanged = (orcidId || null) !== (member.orcid_id || null);

        await env.DB.prepare(`
          UPDATE members
          SET display_name = ?,
              institution = ?,
              research_field = ?,
              orcid_id = ?,
              orcid_verified = CASE WHEN ? THEN 0 ELSE orcid_verified END,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).bind(
          displayName,
          institution || null,
          researchField || null,
          orcidId || null,
          orcidChanged ? 1 : 0,
          member.id
        ).run();

        await logAudit(env, member.id, 'UPDATE_PROFILE', 'member', member.id, {
          orcidChanged
        });

        return json({ ok: true, message: 'Profil & ORCID iD berjaya disimpan.' });
      }

      // 6. API Admin: Segerakkan Zenodo Sekarang
      if (path === '/api/admin/sync-zenodo' && method === 'POST') {
        const member = await getCurrentMember(request, env);
        if (!member || (member.role !== 'admin' && member.role !== 'secondary_admin')) {
          return json({ ok: false, error: 'Akses pentadbir diperlukan.' }, 403);
        }

        const result = await syncAllCommunities(env);
        await logAudit(env, member.id, 'SYNC_ZENODO_MANUAL', 'zenodo', null, result);
        return json({ ok: true, result });
      }

      // 7. API Admin: Senarai & Kelulusan Ahli (Serta Pelantikan Admin Kedua)
      if (path === '/api/admin/members' && method === 'GET') {
        const member = await getCurrentMember(request, env);
        if (!member || (member.role !== 'admin' && member.role !== 'secondary_admin')) {
          return json({ ok: false, error: 'Akses pentadbir diperlukan.' }, 403);
        }

        const { results } = await env.DB.prepare(
          `SELECT id, email, display_name, institution, research_field, orcid_id, role, status, created_at FROM members ORDER BY created_at DESC`
        ).all();

        return json({ ok: true, members: results || [] });
      }

      if (path === '/api/admin/members/update' && method === 'POST') {
        const actor = await getCurrentMember(request, env);
        if (!actor || (actor.role !== 'admin' && actor.role !== 'secondary_admin')) {
          return json({ ok: false, error: 'Akses pentadbir diperlukan.' }, 403);
        }

        let body;
        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: 'Format JSON tidak sah.' }, 400);
        }

        const { memberId, status, role, displayName, email } = body;
        if (!memberId) return json({ ok: false, error: 'memberId diperlukan.' }, 400);

        if (status !== undefined) {
          if (!ALLOWED_STATUSES.has(status)) {
            return json({ ok: false, error: 'Nilai status tidak sah.' }, 400);
          }
          await env.DB.prepare(`UPDATE members SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
            .bind(status, memberId).run();
        }

        if (role !== undefined && actor.role === 'admin') {
          if (!ALLOWED_ROLES.has(role)) {
            return json({ ok: false, error: 'Nilai peranan tidak sah.' }, 400);
          }
          await env.DB.prepare(`UPDATE members SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
            .bind(role, memberId).run();
        }

        if (displayName && email && actor.role === 'admin') {
          await env.DB.prepare(`UPDATE members SET display_name = ?, email = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
            .bind(String(displayName).trim().slice(0, 120), String(email).trim().toLowerCase(), memberId).run();
        }

        await logAudit(env, actor.id, 'UPDATE_MEMBER', 'member', memberId, { status, role });
        return json({ ok: true });
      }

      // 7b. Favicon redirect (robots.txt & sitemap.xml dihidangkan terus dari public/)
      if (path === '/favicon.ico') {
        return Response.redirect(new URL('/assets/xr6-hq-logo.svg', request.url).toString(), 301);
      }

      // 8. Hidangkan Fail Statik (Folder public/)
      if (env.ASSETS) {
        return await env.ASSETS.fetch(request);
      }

      return new Response('XR6 Labs HQ Worker Active', { status: 200 });
    } catch (err) {
      console.error('Worker error:', err);
      return json({ ok: false, error: 'Ralat pelayan dalaman. Sila cuba sebentar lagi.' }, 500);
    }
  }
};
