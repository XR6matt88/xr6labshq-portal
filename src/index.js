import {
  json,
  sha256Hex,
  generateToken,
  buildSessionCookie,
  clearSessionCookie,
  getCurrentMember,
  verifyTurnstile,
  consumeRateLimit,
  logAudit
} from './lib.js';
import { sendMagicLinkEmail } from './mail.js';
import { syncAllCommunities } from './sync.js';

const ALLOWED_MEMBER_STATUSES = new Set(['pending', 'active', 'suspended']);
const ALLOWED_ASSIGNABLE_ROLES = new Set(['member', 'secondary_admin']);
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default {
  async scheduled(event, env, ctx) {
    const cleanup = env.DB
      ? env.DB.prepare(`DELETE FROM request_rate_limits WHERE window_start < ?`)
          .bind(Math.floor(Date.now() / 1000) - 24 * 60 * 60).run()
      : Promise.resolve();
    ctx.waitUntil(Promise.all([syncAllCommunities(env), cleanup]));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
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

        if (conditions.length > 0) query += ` WHERE ` + conditions.join(' AND ');
        query += ` ORDER BY publication_date DESC, synced_at DESC LIMIT 100`;

        const { results } = await env.DB.prepare(query).bind(...params).all();
        return json({ ok: true, records: results || [] });
      }

      if (path === '/api/auth/request-link' && method === 'POST') {
        let body;
        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: 'Permintaan tidak sah.' }, 400);
        }
        const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
        const turnstileToken = typeof body?.turnstileToken === 'string' ? body.turnstileToken : '';

        if (email.length > 254 || !EMAIL_PATTERN.test(email)) {
          return json({ ok: false, error: 'Alamat e-mel tidak sah.' }, 400);
        }

        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        const humanOk = await verifyTurnstile(turnstileToken, ip, env, url.hostname);
        if (!humanOk) {
          return json({ ok: false, error: 'Pengesahan keselamatan Turnstile gagal.' }, 403);
        }

        const ipAllowed = await consumeRateLimit(env.DB, 'request-link-ip', ip, 10);
        const emailAllowed = await consumeRateLimit(env.DB, 'request-link-email', email, 3);
        if (!ipAllowed || !emailAllowed) {
          return json(
            { ok: false, error: 'Terlalu banyak permintaan. Sila cuba lagi dalam masa sejam.' },
            429,
            { 'Retry-After': '3600' }
          );
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

        if (member.status === 'suspended') {
          return Response.redirect(`${url.origin}/login?error=account_suspended`, 302);
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

      if (path === '/api/auth/logout' && method === 'POST') {
        return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookie() });
      }

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

      if (path === '/api/admin/sync-zenodo' && method === 'POST') {
        const member = await getCurrentMember(request, env);
        if (!member || (member.role !== 'admin' && member.role !== 'secondary_admin')) {
          return json({ ok: false, error: 'Akses pentadbir diperlukan.' }, 403);
        }

        const result = await syncAllCommunities(env);
        await logAudit(env, member.id, 'SYNC_ZENODO_MANUAL', 'zenodo', null, result);
        return json({ ok: true, result });
      }

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
          return json({ ok: false, error: 'Permintaan tidak sah.' }, 400);
        }

        const memberId = typeof body?.memberId === 'string' ? body.memberId.trim() : '';
        if (!memberId || memberId.length > 128) {
          return json({ ok: false, error: 'memberId tidak sah.' }, 400);
        }

        const target = await env.DB.prepare(`SELECT id, role FROM members WHERE id = ?`)
          .bind(memberId).first();
        if (!target) return json({ ok: false, error: 'Ahli tidak ditemui.' }, 404);
        if (target.role === 'admin') {
          return json({ ok: false, error: 'Akaun pentadbir utama dilindungi daripada perubahan melalui endpoint ini.' }, 403);
        }
        if (memberId === actor.id && (body.status !== undefined || body.role !== undefined)) {
          return json({ ok: false, error: 'Anda tidak boleh mengubah status atau peranan akaun sendiri.' }, 400);
        }

        const updates = [];
        const values = [];

        if (body.status !== undefined) {
          if (!ALLOWED_MEMBER_STATUSES.has(body.status)) {
            return json({ ok: false, error: 'Status ahli tidak sah.' }, 400);
          }
          if (actor.role === 'secondary_admin' && target.role !== 'member') {
            return json({ ok: false, error: 'Secondary admin hanya boleh mengemas kini status ahli biasa.' }, 403);
          }
          updates.push('status = ?');
          values.push(body.status);
        }

        if (body.role !== undefined) {
          if (actor.role !== 'admin') {
            return json({ ok: false, error: 'Hanya admin utama boleh mengubah peranan.' }, 403);
          }
          if (!ALLOWED_ASSIGNABLE_ROLES.has(body.role)) {
            return json({ ok: false, error: 'Peranan ahli tidak sah.' }, 400);
          }
          updates.push('role = ?');
          values.push(body.role);
        }

        let profileUpdated = false;
        if (body.displayName !== undefined || body.email !== undefined) {
          if (actor.role !== 'admin') {
            return json({ ok: false, error: 'Hanya admin utama boleh mengubah profil ahli.' }, 403);
          }
          if (body.displayName !== undefined) {
            if (typeof body.displayName !== 'string' || !body.displayName.trim() || body.displayName.trim().length > 120) {
              return json({ ok: false, error: 'Nama paparan tidak sah.' }, 400);
            }
            updates.push('display_name = ?');
            values.push(body.displayName.trim());
          }
          if (body.email !== undefined) {
            if (typeof body.email !== 'string' || body.email.trim().length > 254 || !EMAIL_PATTERN.test(body.email.trim())) {
              return json({ ok: false, error: 'Alamat e-mel tidak sah.' }, 400);
            }
            updates.push('email = ?');
            values.push(body.email.trim().toLowerCase());
          }
          profileUpdated = true;
        }

        if (updates.length === 0) {
          return json({ ok: false, error: 'Tiada perubahan sah diberikan.' }, 400);
        }

        updates.push('updated_at = CURRENT_TIMESTAMP');
        values.push(memberId);
        await env.DB.prepare(`UPDATE members SET ${updates.join(', ')} WHERE id = ?`)
          .bind(...values).run();

        await logAudit(env, actor.id, 'UPDATE_MEMBER', 'member', memberId, {
          status: body.status,
          role: body.role,
          profileUpdated
        });
        return json({ ok: true });
      }

      if (env.ASSETS) return await env.ASSETS.fetch(request);
      return new Response('XR6 Labs HQ Worker Active', { status: 200 });
    } catch (err) {
      console.error('Worker request failed', err);
      return json({ ok: false, error: 'Ralat pelayan. Sila cuba lagi kemudian.' }, 500);
    }
  }
};
