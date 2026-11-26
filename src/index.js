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
const MAX_ANNOUNCEMENT_MEDIA_BYTES = 50 * 1024 * 1024; // Had selamat 50 MB setiap fail
const MAX_ATTACHMENTS_PER_POST = 10;

function detectMediaCategory(mime, filename) {
  const m = String(mime || '').toLowerCase();
  const ext = String(filename || '').toLowerCase().split('.').pop() || '';
  if (m.startsWith('image/') || ['jpg', 'jpeg', 'png', 'webp', 'gif', 'svg'].includes(ext)) {
    return 'image';
  }
  if (m.startsWith('audio/') || ['mp3', 'wav', 'm4a', 'aac', 'ogg', 'flac', 'opus'].includes(ext)) {
    return 'audio';
  }
  if (m.startsWith('video/') || ['mp4', 'webm', 'mov', 'm4v'].includes(ext)) {
    return 'video';
  }
  return 'document';
}

function normaliseAnnouncementRow(row) {
  let attachments = [];
  if (row.media_type === 'multi' && row.media_filename) {
    try {
      const parsed = JSON.parse(row.media_filename);
      if (Array.isArray(parsed)) {
        attachments = parsed
          .filter((a) => a && typeof a.key === 'string' && a.key.startsWith('announcements/'))
          .map((a) => ({
            key: a.key,
            filename: String(a.filename || 'lampiran'),
            mime: String(a.mime || 'application/octet-stream'),
            type: String(a.type || detectMediaCategory(a.mime, a.filename))
          }));
      }
    } catch {}
  }

  if (attachments.length === 0 && row.media_key) {
    attachments = [
      {
        key: row.media_key,
        filename: row.media_filename || 'lampiran',
        mime: row.media_mime || 'application/octet-stream',
        type: row.media_type && row.media_type !== 'multi'
          ? row.media_type
          : detectMediaCategory(row.media_mime, row.media_filename)
      }
    ];
  }

  return {
    ...row,
    attachments
  };
}

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
        let body;
        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: 'Format JSON tidak sah.' }, 400);
        }

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

      // 4. API Auth: Log Keluar (padam sesi D1 + cookie)
      if (path === '/api/auth/logout' && method === 'POST') {
        await deleteCurrentSession(request, env);
        return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie() });
      }

      // 5. API Profil Ahli Semasa (/api/me & /api/me/profile)
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

      if (path === '/api/me/profile' && method === 'POST') {
        const member = await getCurrentMember(request, env);
        if (!member) return json({ ok: false, error: 'Tidak log masuk.' }, 401);

        let body;
        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: 'Format JSON tidak sah.' }, 400);
        }

        const displayName = String(body.displayName || '').trim().slice(0, 120);
        const institution = String(body.institution || '').trim().slice(0, 160);
        const researchField = String(body.researchField || '').trim().slice(0, 160);
        const orcidId = normaliseOrcid(body.orcidId);

        if (!displayName) {
          return json({ ok: false, error: 'Nama paparan wajib diisi.' }, 400);
        }
        if (!isValidOrcid(orcidId)) {
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

        await logAudit(env, member.id, 'UPDATE_PROFILE', 'member', member.id, { orcidChanged });
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

      // 8. API Pengumuman & Aktiviti (Paparan Awam + Diagnostik + Muat Naik R2 Raw PUT + Siar Multi-Fail)
      if (path === '/api/announcements' && method === 'GET') {
        const { results } = await env.DB.prepare(
          `SELECT id, title, category, description, media_type, media_key, media_filename, media_mime, activity_date, created_at
           FROM announcements WHERE is_active = 1 ORDER BY activity_date DESC, created_at DESC`
        ).all();
        const announcements = (results || []).map(normaliseAnnouncementRow);
        return json({ ok: true, announcements });
      }

      if (path === '/api/admin/announcements/status' && method === 'GET') {
        const member = await getCurrentMember(request, env);
        if (!member || (member.role !== 'admin' && member.role !== 'secondary_admin')) {
          return json({ ok: false, error: 'Akses pentadbir diperlukan.' }, 403);
        }

        let dbReady = false;
        let dbError = null;
        try {
          await env.DB.prepare(`SELECT COUNT(*) AS total FROM announcements`).first();
          dbReady = true;
        } catch (err) {
          dbError = err?.message || 'Jadual announcements gagal diakses.';
        }

        return json({
          ok: true,
          hasMediaBucket: Boolean(env.MEDIA_BUCKET),
          dbReady,
          dbError,
          maxUploadMB: Math.round(MAX_ANNOUNCEMENT_MEDIA_BYTES / (1024 * 1024)),
          maxFiles: MAX_ATTACHMENTS_PER_POST
        });
      }

      if (path === '/api/admin/announcements/media' && method === 'PUT') {
        const member = await getCurrentMember(request, env);
        if (!member || (member.role !== 'admin' && member.role !== 'secondary_admin')) {
          return json({ ok: false, error: 'Akses ditolak: Sila log masuk sebagai Admin atau Second Admin.' }, 403);
        }

        if (!env.MEDIA_BUCKET) {
          return json({
            ok: false,
            error: 'Storan MEDIA_BUCKET (R2: xr6-announcements-media) belum disambungkan di Cloudflare Workers.'
          }, 500);
        }

        const contentLen = Number(request.headers.get('Content-Length') || 0);
        if (contentLen > MAX_ANNOUNCEMENT_MEDIA_BYTES) {
          return json({
            ok: false,
            error: `Saiz fail (${(contentLen / (1024 * 1024)).toFixed(1)} MB) melebihi had maksimum 50 MB.`
          }, 413);
        }

        let rawFilename = 'lampiran';
        try {
          rawFilename = decodeURIComponent(request.headers.get('X-Media-Name') || 'lampiran');
        } catch {
          rawFilename = request.headers.get('X-Media-Name') || 'lampiran';
        }
        const mediaFilename = rawFilename.slice(0, 180) || 'lampiran';
        const mediaMime = (request.headers.get('X-Media-Mime') || 'application/octet-stream').slice(0, 120);
        const mediaType = detectMediaCategory(mediaMime, mediaFilename);
        const safeName = mediaFilename.replace(/[^a-zA-Z0-9._-]/g, '_') || 'lampiran';
        const mediaKey = `announcements/${crypto.randomUUID()}-${safeName}`;

        try {
          if (contentLen > 0 && request.body) {
            await env.MEDIA_BUCKET.put(mediaKey, request.body, {
              httpMetadata: { contentType: mediaMime }
            });
          } else {
            const buf = await request.arrayBuffer();
            if (!buf || buf.byteLength === 0) {
              return json({ ok: false, error: 'Fail kosong atau tiada kandungan diterima.' }, 400);
            }
            if (buf.byteLength > MAX_ANNOUNCEMENT_MEDIA_BYTES) {
              return json({ ok: false, error: 'Saiz fail melebihi had maksimum 50 MB.' }, 413);
            }
            await env.MEDIA_BUCKET.put(mediaKey, buf, {
              httpMetadata: { contentType: mediaMime }
            });
          }
        } catch (r2Err) {
          console.error('R2 PUT media error:', r2Err);
          return json({
            ok: false,
            error: `Gagal menyimpan fail ke R2 MEDIA_BUCKET: ${r2Err?.message || 'Ralat storan R2'}`
          }, 500);
        }

        return json({
          ok: true,
          mediaKey,
          mediaFilename,
          mediaMime,
          mediaType
        });
      }

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
        headers.set('Accept-Ranges', 'bytes');
        headers.set('X-Content-Type-Options', 'nosniff');
        headers.set('Cache-Control', 'public, max-age=3600');
        return new Response(object.body, { headers });
      }

      if (path === '/api/admin/announcements' && method === 'POST') {
        const member = await getCurrentMember(request, env);
        if (!member || (member.role !== 'admin' && member.role !== 'secondary_admin')) {
          return json({ ok: false, error: 'Akses ditolak: Sila log masuk sebagai Admin atau Second Admin.' }, 403);
        }

        const ct = (request.headers.get('Content-Type') || '').toLowerCase();
        const id = crypto.randomUUID();
        let title = '';
        let category = 'Aktiviti';
        let description = '';
        let activityDate = new Date().toISOString().slice(0, 10);
        let mediaType = 'none';
        let mediaKey = null;
        let mediaFilename = null;
        let mediaMime = null;
        const uploadedKeysToCleanup = [];

        if (ct.includes('application/json')) {
          let body;
          try {
            body = await request.json();
          } catch {
            return json({ ok: false, error: 'Format JSON pengumuman tidak sah.' }, 400);
          }

          title = String(body.title || '').trim().slice(0, 200);
          category = String(body.category || 'Aktiviti').trim().slice(0, 80) || 'Aktiviti';
          description = String(body.description || '').trim().slice(0, 10000);
          const rawDate = String(body.activity_date || '').trim();
          if (/^\d{4}-\d{2}-\d{2}$/.test(rawDate)) activityDate = rawDate;

          const incomingAttachments = Array.isArray(body.attachments) ? body.attachments : [];
          const cleanAttachments = [];

          for (const item of incomingAttachments.slice(0, MAX_ATTACHMENTS_PER_POST)) {
            if (!item || typeof item.key !== 'string') continue;
            const candidateKey = item.key.trim();
            if (!candidateKey.startsWith('announcements/') || candidateKey.includes('..')) {
              return json({ ok: false, error: 'Rujukan key lampiran tidak sah.' }, 400);
            }
            const fname = String(item.filename || 'lampiran').slice(0, 180);
            const fmime = String(item.mime || 'application/octet-stream').slice(0, 120);
            const ftype = String(item.type || detectMediaCategory(fmime, fname));
            cleanAttachments.push({ key: candidateKey, filename: fname, mime: fmime, type: ftype });
            uploadedKeysToCleanup.push(candidateKey);
          }

          if (cleanAttachments.length === 0 && body.media_key) {
            const candidateKey = String(body.media_key).trim();
            if (!candidateKey.startsWith('announcements/') || candidateKey.includes('..')) {
              return json({ ok: false, error: 'Rujukan media_key tidak sah.' }, 400);
            }
            const fname = String(body.media_filename || 'lampiran').slice(0, 180);
            const fmime = String(body.media_mime || 'application/octet-stream').slice(0, 120);
            const ftype = String(body.media_type || detectMediaCategory(fmime, fname));
            cleanAttachments.push({ key: candidateKey, filename: fname, mime: fmime, type: ftype });
            uploadedKeysToCleanup.push(candidateKey);
          }

          if (cleanAttachments.length === 1) {
            mediaKey = cleanAttachments[0].key;
            mediaFilename = cleanAttachments[0].filename;
            mediaMime = cleanAttachments[0].mime;
            mediaType = cleanAttachments[0].type;
          } else if (cleanAttachments.length > 1) {
            mediaType = 'multi';
            mediaKey = cleanAttachments[0].key;
            mediaMime = cleanAttachments[0].mime;
            mediaFilename = JSON.stringify(cleanAttachments);
          }
        } else {
          let formData;
          try {
            formData = await request.formData();
          } catch (err) {
            console.error('FormData parse error:', err);
            return json({ ok: false, error: 'Borang atau fail gagal diproses.' }, 400);
          }

          title = String(formData.get('title') || '').trim().slice(0, 200);
          category = String(formData.get('category') || 'Aktiviti').trim().slice(0, 80) || 'Aktiviti';
          description = String(formData.get('description') || '').trim().slice(0, 10000);
          const rawDate = String(formData.get('activity_date') || '').trim();
          if (/^\d{4}-\d{2}-\d{2}$/.test(rawDate)) activityDate = rawDate;

          const file = formData.get('media_file');
          if (file && typeof file === 'object' && file.size > 0) {
            if (file.size > MAX_ANNOUNCEMENT_MEDIA_BYTES) {
              return json({ ok: false, error: 'Saiz fail melebihi had maksimum 50 MB.' }, 413);
            }
            if (!env.MEDIA_BUCKET) {
              return json({ ok: false, error: 'Storan MEDIA_BUCKET belum disambungkan di Cloudflare.' }, 500);
            }
            mediaMime = file.type || 'application/octet-stream';
            mediaFilename = file.name || 'lampiran';
            mediaType = detectMediaCategory(mediaMime, mediaFilename);
            const safeName = mediaFilename.replace(/[^a-zA-Z0-9._-]/g, '_') || 'lampiran';
            mediaKey = `announcements/${id}-${safeName}`;
            await env.MEDIA_BUCKET.put(mediaKey, file, {
              httpMetadata: { contentType: mediaMime }
            });
            uploadedKeysToCleanup.push(mediaKey);
          }
        }

        if (!title) {
          return json({ ok: false, error: 'Tajuk pengumuman wajib diisi.' }, 400);
        }

        try {
          await env.DB.prepare(`
            INSERT INTO announcements (id, title, category, description, media_type, media_key, media_filename, media_mime, activity_date, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(id, title, category, description, mediaType, mediaKey, mediaFilename, mediaMime, activityDate, member.email).run();
        } catch (dbErr) {
          console.error('D1 insert announcement error:', dbErr);
          if (env.MEDIA_BUCKET) {
            for (const k of uploadedKeysToCleanup) {
              await env.MEDIA_BUCKET.delete(k).catch(() => {});
            }
          }
          return json({
            ok: false,
            error: `Gagal menyimpan rekod ke pangkalan data D1: ${dbErr?.message || 'Ralat D1'}`
          }, 500);
        }

        await logAudit(env, member.id, 'CREATE_ANNOUNCEMENT', 'announcement', id, {
          title,
          mediaType,
          fileCount: uploadedKeysToCleanup.length
        });
        return json({ ok: true, id });
      }

      if (path.startsWith('/api/admin/announcements/') && method === 'DELETE') {
        const member = await getCurrentMember(request, env);
        if (!member || (member.role !== 'admin' && member.role !== 'secondary_admin')) {
          return json({ ok: false, error: 'Akses ditolak.' }, 403);
        }

        const id = path.replace('/api/admin/announcements/', '').trim();
        const existing = await env.DB.prepare(
          `SELECT media_type, media_key, media_filename FROM announcements WHERE id = ?`
        ).bind(id).first();

        if (existing && env.MEDIA_BUCKET) {
          const keysToDelete = new Set();
          if (existing.media_key) keysToDelete.add(existing.media_key);
          if (existing.media_type === 'multi' && existing.media_filename) {
            try {
              const parsed = JSON.parse(existing.media_filename);
              if (Array.isArray(parsed)) {
                parsed.forEach((a) => {
                  if (a && typeof a.key === 'string') keysToDelete.add(a.key);
                });
              }
            } catch {}
          }
          for (const k of keysToDelete) {
            await env.MEDIA_BUCKET.delete(k).catch(() => {});
          }
        }

        await env.DB.prepare(`DELETE FROM announcements WHERE id = ?`).bind(id).run();
        await logAudit(env, member.id, 'DELETE_ANNOUNCEMENT', 'announcement', id, {});
        return json({ ok: true });
      }

      // 8b. Favicon redirect (robots.txt, sitemap.xml & llms.txt dihidangkan terus dari public/)
      if (path === '/favicon.ico') {
        return Response.redirect(new URL('/assets/xr6-hq-logo.svg', request.url).toString(), 301);
      }

      // 9. Hidangkan Fail Statik (Folder public/)
      if (env.ASSETS) {
        return await env.ASSETS.fetch(request);
      }

      return new Response('XR6 Labs HQ Worker Active', { status: 200 });
    } catch (err) {
      console.error('Worker error:', err);
      return json({ ok: false, error: 'Ralat pelayan dalaman: ' + (err?.message || 'Sila cuba sebentar lagi.') }, 500);
    }
  }
};
