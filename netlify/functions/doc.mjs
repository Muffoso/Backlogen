// Lagrar sidans innehåll i Netlify Blobs.
// Innehållet krypteras i webbläsaren – servern ser aldrig klartext eller lösenord.
// Servern lagrar bara en hash av en åtkomsttoken som härleds ur lösenordet.

import { getStore } from '@netlify/blobs';
import { createHash, timingSafeEqual } from 'node:crypto';

const DOC_KEY = 'doc';
const MAX_BYTES = 5 * 1024 * 1024;

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

function authorized(req, doc) {
  const m = /^Bearer (.+)$/.exec(req.headers.get('authorization') || '');
  if (!m || !doc) return false;
  const a = Buffer.from(sha256(m[1]), 'hex');
  const b = Buffer.from(doc.tokenHash, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

const isB64 = (s, max = MAX_BYTES) => typeof s === 'string' && s.length > 0 && s.length <= max && /^[A-Za-z0-9+/]+=*$/.test(s);
const validIter = (n) => Number.isInteger(n) && n >= 100000 && n <= 10000000;

export default async (req) => {
  const store = getStore({ name: 'backlogen', consistency: 'strong' });
  const doc = await store.get(DOC_KEY, { type: 'json' });
  const path = new URL(req.url).pathname;

  // Publik metadata: om sidan är skapad, och salt för nyckelhärledning (saltet är inte hemligt).
  if (path === '/api/meta' && req.method === 'GET') {
    return json(doc ? { initialized: true, salt: doc.salt, iter: doc.iter } : { initialized: false });
  }

  if (path !== '/api/doc') return json({ error: 'Not found' }, 404);

  if (req.method === 'GET') {
    if (!authorized(req, doc)) return json({ error: 'Unauthorized' }, 401);
    return json({ iv: doc.iv, data: doc.data, version: doc.version, updated: doc.updated });
  }

  let body;
  try { body = await req.json(); } catch { return json({ error: 'Bad JSON' }, 400); }
  if (!isB64(body.iv, 64) || !isB64(body.data)) return json({ error: 'Bad payload' }, 400);

  // Första gången: skapa dokumentet. Bara tillåtet om inget finns sedan tidigare.
  if (req.method === 'POST') {
    if (doc) return json({ error: 'Already initialized' }, 409);
    if (!isB64(body.salt, 64) || !validIter(body.iter) || !isB64(body.token, 128)) return json({ error: 'Bad payload' }, 400);
    const created = {
      salt: body.salt, iter: body.iter, tokenHash: sha256(body.token),
      iv: body.iv, data: body.data, version: 1, updated: new Date().toISOString(),
    };
    await store.setJSON(DOC_KEY, created);
    return json({ version: created.version, updated: created.updated }, 201);
  }

  // Spara ändringar (och ev. nytt lösenord).
  if (req.method === 'PUT') {
    if (!authorized(req, doc)) return json({ error: 'Unauthorized' }, 401);
    if (body.baseVersion !== doc.version) return json({ error: 'Conflict', version: doc.version }, 409);

    const next = { ...doc, iv: body.iv, data: body.data, version: doc.version + 1, updated: new Date().toISOString() };
    if (body.newAuth) {
      const { salt, iter, token } = body.newAuth;
      if (!isB64(salt, 64) || !validIter(iter) || !isB64(token, 128)) return json({ error: 'Bad payload' }, 400);
      Object.assign(next, { salt, iter, tokenHash: sha256(token) });
    }
    // Spara föregående version som backup.
    await store.setJSON('backup', doc);
    await store.setJSON(DOC_KEY, next);
    return json({ version: next.version, updated: next.updated });
  }

  return json({ error: 'Method not allowed' }, 405);
};

export const config = { path: ['/api/meta', '/api/doc'] };
