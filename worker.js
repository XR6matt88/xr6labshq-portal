function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...extraHeaders
    }
  });
}

async function sha256Hex(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function generateToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx > -1) {
      const key = pair.slice(0, idx).trim();
      const val = pair.slice(idx + 1).trim();
      cookies[key] = decodeURIComponent(val);
    }
  });
  return cookies;
}

function buildSessionCookie(token, maxAgeSeconds = 60 * 60 * 24 * 7) {
  return `xr6_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

function clearSessionCookie() {
  return `xr6_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

async function getCurrentMember(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie'));
  const sessionToken = cookies['xr6_session'];
  if (!sessionToken || !env.DB) return null;

  const tokenHash = await sha256Hex(sessionToken);
  const row = await env.DB.prepare(`
    SELECT m.* FROM sessions s
    JOIN members m ON s.member_id = m.id
    WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP
  `).bind(tokenHash).first();

  return row || null;
}

async function verifyTurnstile(token, ip, env) {
  if (!env.TURNSTILE_SECRET_KEY) return true;
  if (!token) return false;

  const formData = new FormData();
  formData.append('secret', env.TURNSTILE_SECRET_KEY);
  formData.append('response', token);
  if (ip) formData.append('remoteip', ip);

  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: formData
  });
  const outcome = await res.json();
  return Boolean(outcome.success);
}

async function logAudit(env, actorId, action, targetType = null, targetId = null, details = {}) {
  if (!env.DB) return;
  await env.DB.prepare(`
    INSERT INTO audit_logs (id, actor_id, action, target_type, target_id, details_json)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    crypto.randomUUID(),
    actorId,
    action,
    targetType,
    targetId,
    JSON.stringify(details)
  ).run();
}

async function sendMagicLinkEmail(env, toEmail, magicUrl) {
  const fromEmail = env.FROM_EMAIL || 'hq@ac.xr6labs.com';
  const apiUrl = env.ZEPTO_API_URL || 'https://api.zeptomail.com/v1.1/email';

  if (!env.ZEPTO_API_KEY) {
    throw new Error('ZEPTO_API_KEY belum ditetapkan dalam Secrets.');
  }

  const payload = {
    from: {
      address: fromEmail,
      name: 'XR6 Labs HQ – Research & Engineering'
    },
    to: [
      {
        email_address: {
          address: toEmail
        }
      }
    ],
    subject: 'Pautan Pengesahan Log Masuk / Login Verification – XR6 Labs HQ',
    htmlbody: `
      <div style="font-family: Arial, sans-serif; background-color: #081210; color: #F1F5F4; padding: 28px; border-radius: 12px; max-width: 560px; margin: auto; border: 1px solid #1A3831;">
        <p style="color: #D7B46A; font-size: 20px; text-align: center; margin-bottom: 16px;">بِسْمِ ٱللَّهِ ٱلرَّحْمَـٰنِ ٱلرَّحِيمِ</p>
        <h2 style="color: #39E58C; margin-top: 0;">XR6 Labs HQ – Research &amp; Engineering</h2>
        <p style="line-height: 1.6; color: #D1DBD8;">
          Assalamualaikum &amp; Salam Sejahtera,<br><br>
          Sila klik butang di bawah untuk mengesahkan alamat e-mel anda dan log masuk ke portal penyelidik <strong>XR6 Labs HQ</strong>. Pautan ini sah selama <strong>15 minit</strong> sahaja.
        </p>
        <div style="text-align: center; margin: 26px 0;">
          <a href="${magicUrl}" style="background-color: #FF6A00; color: #081210; font-weight: bold; text-decoration: none; padding: 12px 24px; border-radius: 8px; display: inline-block;">
            Sahkan &amp; Log Masuk / Verify &amp; Login
          </a>
        </div>
        <p style="font-size: 12px; color: #8FA39E; line-height: 1.5;">
          Jika anda tidak meminta pautan ini, sila abaikan e-mel ini.<br>
          XR6 Labs HQ • 26A, Kg. Banggol Petai, 06700 Pendang, Kedah Darul Aman, Malaysia.
        </p>
      </div>
    `
  };

  const response = await fetch(apiUrl, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': env.ZEPTO_API_KEY
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`ZeptoMail Error (${response.status}): ${errText}`);
  }

  return true;
}

function normaliseHit(hit, communitySlug, communityTitle) {
  const metadata = hit.metadata || {};
  const creators = (metadata.creators || []).map(c => {
    const cleanOrcid = c.orcid ? String(c.orcid).replace(/^https?:\/\/orcid\.org\//i, '').trim() : null;
    return {
      name: c.name || 'Unknown Author',
      affiliation: c.affiliation || '',
      orcid: cleanOrcid
    };
  });

  let resourceType = 'publication';
  if (metadata.resource_type) {
    if (metadata.resource_type.id) {
      resourceType = metadata.resource_type.id;
    } else if (metadata.resource_type.subtype) {
      resourceType = `${metadata.resource_type.type}-${metadata.resource_type.subtype}`;
    } else if (metadata.resource_type.type) {
      resourceType = metadata.resource_type.type;
    }
  }

  return {
    zenodo_id: String(hit.id),
    concept_doi: hit.conceptdoi || null,
    version_doi: hit.doi || metadata.doi || '',
    community_slug: communitySlug,
    community_title: communityTitle,
    title: metadata.title || 'Untitled Record',
    abstract: metadata.description || '',
    resource_type: resourceType,
    publication_date: metadata.publication_date || '',
    license_id: metadata.license?.id || null,
    access_right: metadata.access_right || 'open',
    zenodo_url: hit.links?.self_html || hit.links?.html || `https://zenodo.org/records/${hit.id}`,
    authors_json: JSON.stringify(creators),
    creators
  };
}

async function syncZenodoCommunity(env, communitySlug, communityTitle) {
  if (!communitySlug || !env.DB) {
    return { ok: false, error: 'Missing communitySlug or DB binding' };
  }

  const apiUrl = `https://zenodo.org/api/records?communities=${encodeURIComponent(communitySlug)}&size=100&sort=mostrecent`;

  try {
    const response = await fetch(apiUrl, {
      headers: {
        'User-Agent': 'XR6-Labs-HQ-Portal/1.0 (mailto:hq@ac.xr6labs.com)',
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Zenodo API HTTP ${response.status}`);
    }

    const payload = await response.json();
    const hits = payload.hits?.hits || [];

    for (const rawHit of hits) {
      const rec = normaliseHit(rawHit, communitySlug, communityTitle);

      await env.DB.prepare(`
        INSERT INTO zenodo_records (
          zenodo_id, concept_doi, version_doi, community_slug, community_title,
          title, abstract, resource_type, publication_date, license_id,
          access_right, zenodo_url, authors_json, synced_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(zenodo_id) DO UPDATE SET
          concept_doi = excluded.concept_doi,
          version_doi = excluded.version_doi,
          community_title = excluded.community_title,
          title = excluded.title,
          abstract = excluded.abstract,
          resource_type = excluded.resource_type,
          publication_date = excluded.publication_date,
          license_id = excluded.license_id,
          access_right = excluded.access_right,
          zenodo_url = excluded.zenodo_url,
          authors_json = excluded.authors_json,
          synced_at = CURRENT_TIMESTAMP
      `).bind(
        rec.zenodo_id,
        rec.concept_doi,
        rec.version_doi,
        rec.community_slug,
        rec.community_title,
        rec.title,
        rec.abstract,
        rec.resource_type,
        rec.publication_date,
        rec.license_id,
        rec.access_right,
        rec.zenodo_url,
        rec.authors_json
      ).run();

      for (const creator of rec.creators) {
        if (creator.orcid) {
          const member = await env.DB.prepare(
            `SELECT id FROM members WHERE orcid_id = ? AND orcid_verified = 1 AND status = 'active'`
          ).bind(creator.orcid).first();

          if (member) {
            await env.DB.prepare(`
              INSERT OR IGNORE INTO member_publications (id, member_id, zenodo_id, match_method)
              VALUES (?, ?, ?, 'orcid_auto')
            `).bind(`${member.id}-${rec.zenodo_id}`, member.id, rec.zenodo_id).run();
          }
        }
      }
    }

    await env.DB.prepare(`
      INSERT INTO sync_logs (id, community_slug, records_fetched, status)
      VALUES (?, ?, ?, 'success')
    `).bind(crypto.randomUUID(), communitySlug, hits.length).run();

    return { ok: true, communitySlug, count: hits.length };
  } catch (err) {
    await env.DB.prepare(`
      INSERT INTO sync_logs (id, community_slug, records_fetched, status, error_message)
      VALUES (?, ?, 0, 'error', ?)
    `).bind(crypto.randomUUID(), communitySlug, err.message).run();

    return { ok: false, communitySlug, error: err.message };
  }
}

async function syncAllCommunities(env) {
  const mainSlug = env.ZENODO_COMMUNITY_SLUG || 'xr6labshqhub';
  const sassiSlug = env.ZENODO_SASSI_SLUG || 'xr6-bsa-sassi';

  const resMain = await syncZenodoCommunity(env, mainSlug, 'XR6 Labs HQ - Research Hub');
  const resSassi = await syncZenodoCommunity(env, sassiSlug, 'XR6 BSA – SASSI Academic Programme');

  return { main: resMain, sassi: resSassi };
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

      if (env.ASSETS) {
        return await env.ASSETS.fetch(request);
      }

      return new Response('XR6 Labs HQ Worker Active', { status: 200 });
    } catch (err) {
      return json({ ok: false, error: err.message }, 500);
    }
  }
};
