import {
  json,
  sha256Hex,
  generateToken,
  buildSessionCookie,
  clearSessionCookie,
  getCurrentMember,
  verifyTurnstile,
  logAudit
} from './lib.js';
import { sendMagicLinkEmail } from './mail.js';
import { syncAllCommunities } from './sync.js';

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

      // 2. API Auth: Minta Pautan Log Masuk (Magic Link)
      if (path === '/api/auth/request-link' && method === 'POST') {
        const body = await request.json();
        const email = (body.email || '').trim().toLowerCase();
        const turnstileToken = body.turnstileToken || '';

        if (!email || !email.includes('@')) {
          return json({ ok: false, error: 'Alamat e-mel tidak sah.' }, 400);
        }

        const ip = request.headers.get('CF-Connecting-IP');
        const humanOk = await verifyTurnstile(turnstileToken, ip, env);
        if (!humanOk) {
          return json({ ok: false, error: 'Pengesahan keselamatan Turnstile gagal.' }, 403);
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

        return json({ ok: true, message: 'Pautan pengesahan telah dihantar ke e-mel anda.' });
      }

      // 3. API Auth: Sahkan Pautan Log Masuk (Magic Link Callback)
      if (path === '/api/auth/verify' && method === 'GET') {
        const rawToken = url.searchParams.get('token') || '';
        if (!rawToken) return Response.redirect(`${url.origin}/login?error=missing_token`, 302);

        const tokenHash = await sha256Hex(rawToken);
        const tokenRow = await env.DB.prepare(`
          SELECT * FROM auth_tokens
          WHERE token_hash = ? AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP
        `).bind(tokenHash).first();

        if (!tokenRow) {
          return Response.redirect(`${url.origin}/login?error=invalid_or_expired`, 302);
        }

        await env.DB.prepare(`UPDATE auth_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?`)
          .bind(tokenRow.id).run();

        let member = await env.DB.prepare(`SELECT * FROM members WHERE email = ?`)
          .bind(tokenRow.email).first();

        if (!member) {
          const newId = crypto.randomUUID();
          const defaultName = tokenRow.email.split('@')[0];
          await env.DB.prepare(`
            INSERT INTO members (id, email, email_verified, display_name, role, status)
            VALUES (?, ?, 1, ?, 'member', 'pending')
          `).bind(newId, tokenRow.email, defaultName).run();
          member = await env.DB.prepare(`SELECT * FROM members WHERE id = ?`).bind(newId).first();
        } else if (!member.email_verified) {
          await env.DB.prepare(`UPDATE members SET email_verified = 1 WHERE id = ?`)
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

      // 4. API Auth: Log Keluar
      if (path === '/api/auth/logout' && method === 'POST') {
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

        const body = await request.json();
        const { memberId, status, role, displayName, email } = body;
        if (!memberId) return json({ ok: false, error: 'memberId diperlukan.' }, 400);

        if (status) {
          await env.DB.prepare(`UPDATE members SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
            .bind(status, memberId).run();
        }
        if (role && actor.role === 'admin') {
          await env.DB.prepare(`UPDATE members SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
            .bind(role, memberId).run();
        }
        if (displayName && email && actor.role === 'admin') {
          await env.DB.prepare(`UPDATE members SET display_name = ?, email = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
            .bind(displayName.trim(), email.trim().toLowerCase(), memberId).run();
        }

        await logAudit(env, actor.id, 'UPDATE_MEMBER', 'member', memberId, { status, role });
        return json({ ok: true });
      }

      // 8. API Pengumuman & Aktiviti (Paparan Awam + Muat Naik/Padam oleh Admin & Second Admin)
      if (path === '/api/announcements' && method === 'GET') {
        const { results } = await env.DB.prepare(
          `SELECT id, title, category, description, media_type, media_key, media_filename, media_mime, activity_date, created_at
           FROM announcements WHERE is_active = 1 ORDER BY activity_date DESC, created_at DESC`
        ).all();
        return json({ ok: true, announcements: results || [] });
      }

      if (path.startsWith('/api/media/') && method === 'GET') {
        const key = decodeURIComponent(path.replace('/api/media/', ''));
        if (!env.MEDIA_BUCKET || !key) return new Response('Media tidak dijumpai', { status: 404 });

        const object = await env.MEDIA_BUCKET.get(key);
        if (!object) return new Response('Fail tidak wujud', { status: 404 });

        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set('etag', object.httpEtag);
        headers.set('Accept-Ranges', 'bytes');
        return new Response(object.body, { headers });
      }

      if (path === '/api/admin/announcements' && method === 'POST') {
        const member = await getCurrentMember(request, env);
        if (!member || (member.role !== 'admin' && member.role !== 'secondary_admin')) {
          return json({ ok: false, error: 'Akses ditolak: Hanya untuk Admin dan Second Admin.' }, 403);
        }

        const formData = await request.formData();
        const title = String(formData.get('title') || '').trim();
        const category = String(formData.get('category') || 'Aktiviti').trim();
        const description = String(formData.get('description') || '').trim();
        const activityDate = String(formData.get('activity_date') || new Date().toISOString().slice(0, 10)).trim();
        const file = formData.get('media_file');

        if (!title) {
          return json({ ok: false, error: 'Tajuk pengumuman wajib diisi.' }, 400);
        }

        const id = crypto.randomUUID();
        let mediaType = 'none';
        let mediaKey = null;
        let mediaFilename = null;
        let mediaMime = null;

        if (file && typeof file === 'object' && file.size > 0) {
          if (!env.MEDIA_BUCKET) {
            return json({ ok: false, error: 'Storan MEDIA_BUCKET belum disambungkan di Cloudflare (R2 Binding).' }, 500);
          }
          mediaMime = file.type || 'application/octet-stream';
          mediaFilename = file.name || 'lampiran';
          if (mediaMime.startsWith('image/')) mediaType = 'image';
          else if (mediaMime.startsWith('audio/')) mediaType = 'audio';
          else if (mediaMime.startsWith('video/')) mediaType = 'video';
          else mediaType = 'document';

          const safeName = mediaFilename.replace(/[^a-zA-Z0-9._-]/g, '_');
          mediaKey = `announcements/${id}-${safeName}`;
          await env.MEDIA_BUCKET.put(mediaKey, await file.arrayBuffer(), {
            httpMetadata: { contentType: mediaMime }
          });
        }

        await env.DB.prepare(`
          INSERT INTO announcements (id, title, category, description, media_type, media_key, media_filename, media_mime, activity_date, created_by)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(id, title, category, description, mediaType, mediaKey, mediaFilename, mediaMime, activityDate, member.email).run();

        await logAudit(env, member.id, 'CREATE_ANNOUNCEMENT', 'announcement', id, { title, mediaType });
        return json({ ok: true, id });
      }

      if (path.startsWith('/api/admin/announcements/') && method === 'DELETE') {
        const member = await getCurrentMember(request, env);
        if (!member || (member.role !== 'admin' && member.role !== 'secondary_admin')) {
          return json({ ok: false, error: 'Akses ditolak.' }, 403);
        }

        const id = path.replace('/api/admin/announcements/', '').trim();
        const existing = await env.DB.prepare(`SELECT media_key FROM announcements WHERE id = ?`).bind(id).first();

        if (existing && existing.media_key && env.MEDIA_BUCKET) {
          await env.MEDIA_BUCKET.delete(existing.media_key);
        }

        await env.DB.prepare(`DELETE FROM announcements WHERE id = ?`).bind(id).run();
        await logAudit(env, member.id, 'DELETE_ANNOUNCEMENT', 'announcement', id, {});
        return json({ ok: true });
      }

      // 9. Hidangkan Fail Statik (Folder public/)
      if (env.ASSETS) {
        return await env.ASSETS.fetch(request);
      }

      return new Response('XR6 Labs HQ Worker Active', { status: 200 });
    } catch (err) {
      return json({ ok: false, error: err.message }, 500);
    }
  }
};
