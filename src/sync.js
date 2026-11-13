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

export async function syncZenodoCommunity(env, communitySlug, communityTitle) {
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

export async function syncAllCommunities(env) {
  const mainSlug = env.ZENODO_COMMUNITY_SLUG || 'xr6labshqhub';
  const sassiSlug = env.ZENODO_SASSI_SLUG || 'xr6-bsa-sassi';

  const resMain = await syncZenodoCommunity(env, mainSlug, 'XR6 Labs HQ - Research Hub');
  const resSassi = await syncZenodoCommunity(env, sassiSlug, 'XR6 BSA – SASSI Academic Programme');

  return { main: resMain, sassi: resSassi };
}
