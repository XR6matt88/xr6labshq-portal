export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...extraHeaders
    }
  });
}

export async function sha256Hex(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function generateToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx > -1) {
      const key = pair.slice(0, idx).trim();
      const val = pair.slice(idx + 1).trim();
      try {
        cookies[key] = decodeURIComponent(val);
      } catch {
        // Ignore malformed cookie values rather than failing the request.
      }
    }
  });
  return cookies;
}

export function buildSessionCookie(token, maxAgeSeconds = 60 * 60 * 24 * 7) {
  return `xr6_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

export function clearSessionCookie() {
  return `xr6_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export async function getCurrentMember(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie'));
  const sessionToken = cookies['xr6_session'];
  if (!sessionToken || !env.DB) return null;

  const tokenHash = await sha256Hex(sessionToken);
  const row = await env.DB.prepare(`
    SELECT m.* FROM sessions s
    JOIN members m ON s.member_id = m.id
    WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP
      AND m.status != 'suspended'
  `).bind(tokenHash).first();

  return row || null;
}

export async function verifyTurnstile(token, ip, env, expectedHostname) {
  // Fail closed: a missing secret must never disable the CAPTCHA check.
  if (!env.TURNSTILE_SECRET_KEY || typeof token !== 'string' || !token || token.length > 2048) {
    return false;
  }

  const formData = new FormData();
  formData.append('secret', env.TURNSTILE_SECRET_KEY);
  formData.append('response', token);
  if (ip) formData.append('remoteip', ip);

  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData,
      signal: AbortSignal.timeout(5000)
    });
    if (!response.ok) return false;
    const outcome = await response.json();
    return Boolean(outcome.success) && (!expectedHostname || outcome.hostname === expectedHostname);
  } catch {
    return false;
  }
}

export async function consumeRateLimit(db, scope, identifier, maxRequests, windowSeconds = 3600) {
  const keyHash = await sha256Hex(`${scope}:${identifier}`);
  const now = Math.floor(Date.now() / 1000);
  const row = await db.prepare(`
    INSERT INTO request_rate_limits (scope, key_hash, window_start, hits)
    VALUES (?, ?, ?, 1)
    ON CONFLICT(scope, key_hash) DO UPDATE SET
      hits = CASE
        WHEN request_rate_limits.window_start <= ? THEN 1
        ELSE request_rate_limits.hits + 1
      END,
      window_start = CASE
        WHEN request_rate_limits.window_start <= ? THEN ?
        ELSE request_rate_limits.window_start
      END
    RETURNING hits
  `).bind(scope, keyHash, now, now - windowSeconds, now - windowSeconds, now).first();

  return Boolean(row && row.hits <= maxRequests);
}

export async function logAudit(env, actorId, action, targetType = null, targetId = null, details = {}) {
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
