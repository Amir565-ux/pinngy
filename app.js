/**
 * Website Pinger - Simple Node.js server
 * Uses only built-in Node modules + native sqlite
 */
import { createServer } from 'node:http';
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const PORT = 8080;
const DB_PATH = join(dirname(fileURLToPath(import.meta.url)), 'data', 'db.sqlite');
const SALT = 'webpinger-salt-v1-fixed!!';

mkdirSync(join(dirname(fileURLToPath(import.meta.url)), 'data'), { recursive: true });
const db = new DatabaseSync(DB_PATH);

// Init schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT);
  CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, url TEXT, interval_ms INTEGER DEFAULT 30000);
  CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, site_id INTEGER, status TEXT, latency REAL, error TEXT, ts TEXT DEFAULT (datetime('now')));
`);

// Create default admin if needed
if (!db.prepare("SELECT id FROM users LIMIT 1").get()) {
  const h = crypto.scryptSync('admin123', SALT, 64).toString('hex');
  db.prepare("INSERT INTO users VALUES (1, ?, ?)").run('admin', h);
}

function resp(res, code, data) {
  res.writeHead(code, {'Content-Type': 'application/json'});
  res.end(JSON.stringify(data));
}
function cookie(req) {
  const m = (req.headers.cookie || '').match(/sess=([^;]+)/);
  return m ? m[1] : null;
}
function setCookie(res, val) {
  res.setHeader('Set-Cookie', `sess=${val}; Path=/; HttpOnly`);
}
function auth(req) {
  const c = cookie(req);
  if (!c) return null;
  try {
    const s = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'data', 'sessions.json'), 'utf8'));
    return s[c] || null;
  } catch { return null; }
}
function saveAuth(tok, user) {
  let s = {};
  try { s = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'data', 'sessions.json'), 'utf8')); } catch {}
  s[tok] = { user, t: Date.now() };
  writeFileSync(join(dirname(fileURLToPath(import.meta.url)), 'data', 'sessions.json'), JSON.stringify(s));
}

const srv = createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;

  // Login
  if (method === 'POST' && url.pathname === '/api/login') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      try {
        const {username, password} = JSON.parse(body);
        const row = db.prepare("SELECT * FROM users WHERE username=?").get(username);
        if (!row) return resp(res, 401, {ok:false, error:'bad credentials'});
        const out = crypto.scryptSync(password, SALT, 64);
        if (!crypto.timingSafeEqual(out, Buffer.from(row.password, 'hex'))) {
          return resp(res, 401, {ok:false, error:'bad credentials'});
        }
        const tok = crypto.randomBytes(32).toString('hex');
        setCookie(res, tok);
        saveAuth(tok, username);
        resp(res, 200, {ok:true, user: username});
      } catch(e) { resp(res, 400, {ok:false, error:e.message}); }
    });
    return;
  }

  // Logout
  if (method === 'POST' && url.pathname === '/api/logout') {
    res.setHeader('Set-Cookie', 'sess=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
    resp(res, 200, {ok:true});
    return;
  }

  // Auth check for API routes
  const session = auth(req);
  if (!session) {
    if (url.pathname.startsWith('/api/')) return resp(res, 401, {ok:false});
  }

  // Get sites with stats
  if (method === 'GET' && url.pathname === '/api/sites') {
    const sites = db.prepare("SELECT * FROM sites ORDER BY id DESC").all();
    const result = sites.map(s => {
      const last = db.prepare("SELECT * FROM history WHERE site_id=? ORDER BY ts DESC LIMIT 1").get(s.id);
      const recent = db.prepare("SELECT status FROM history WHERE site_id=? AND ts > datetime('now', '-1 day')").all(s.id);
      const up = recent.filter(x => x.status === 'up').length;
      return {
        ...s,
        last_status: last?.status || null,
        last_latency: last?.latency || null,
        uptime_pct: recent.length ? Math.round(up/recent.length*100) : null
      };
    });
    resp(res, 200, {sites: result});
    return;
  }

  // Add site
  if (method === 'POST' && url.pathname === '/api/sites') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      try {
        const {name, url: siteUrl, interval_ms = 30000} = JSON.parse(body);
        db.prepare("INSERT INTO sites (name, url, interval_ms) VALUES (?, ?, ?)").run(name, siteUrl, interval_ms);
        resp(res, 201, {ok:true});
      } catch(e) { resp(res, 400, {ok:false, error:e.message}); }
    });
    return;
  }

  // Delete site
  if (method === 'DELETE' && url.pathname.startsWith('/api/site/')) {
    const id = url.pathname.split('/').pop();
    db.prepare("DELETE FROM sites WHERE id=?").run(id);
    db.prepare("DELETE FROM history WHERE site_id=?").run(id);
    resp(res, 200, {ok:true});
    return;
  }

  // Ping
  if (method === 'POST' && url.pathname === '/api/ping') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      try {
        const {url: pingUrl, site_id} = JSON.parse(body);
        if (!pingUrl) return resp(res, 400, {ok:false});
        const t0 = Date.now();
        const r = await fetch(pingUrl, {signal: AbortSignal.timeout(10000), redirect: 'follow'});
        const latency = Date.now() - t0;
        const ok = r.ok;
        if (site_id) {
          db.prepare("INSERT INTO history (site_id, status, latency, error) VALUES (?, ?, ?, ?)")
            .run(site_id, ok ? 'up' : 'down', latency, ok ? null : String(r.status));
        }
        resp(res, 200, {ok, latency, status: String(r.status)});
      } catch(e) {
        if (site_id) {
          db.prepare("INSERT INTO history (site_id, status, latency, error) VALUES (?, ?, ?, ?)")
            .run(site_id, 'down', null, e.message);
        }
        resp(res, 200, {ok:false, latency:null, error:e.message});
      }
    });
    return;
  }

  // History
  if (method === 'GET' && url.pathname.startsWith('/api/history/')) {
    const id = url.pathname.split('/').pop();
    const rows = db.prepare("SELECT * FROM history WHERE site_id=? ORDER BY ts DESC LIMIT 100").all(id);
    resp(res, 200, {history: rows});
    return;
  }

  // Static files
  const filePath = join(dirname(fileURLToPath(import.meta.url)), 'public', url.pathname === '/' ? 'index.html' : url.pathname.slice(1));
  if (existsSync(filePath)) {
    const ext = filePath.split('.').pop();
    const mime = {html:'text/html', css:'text/css', js:'application/javascript', svg:'image/svg+xml'}[ext] || 'application/octet-stream';
    res.writeHead(200, {'Content-Type': mime});
    res.end(readFileSync(filePath));
    return;
  }
  res.writeHead(404);
  res.end('not found');
});

// Background pinger
async function loop() {
  while (true) {
    try {
      const sites = db.prepare("SELECT * FROM sites").all();
      for (const s of sites) {
        try {
          const t0 = Date.now();
          const r = await fetch(s.url, {signal: AbortSignal.timeout(10000), redirect: 'follow'});
          const latency = Date.now() - t0;
          db.prepare("INSERT INTO history (site_id, status, latency, error) VALUES (?, ?, ?, ?)")
            .run(s.id, r.ok ? 'up' : 'down', latency, r.ok ? null : String(r.status));
          console.log(`[${new Date().toISOString()}] ${s.name}: ${r.ok?'UP':'DOWN'} ${latency}ms`);
        } catch(e) {
          db.prepare("INSERT INTO history (site_id, status, latency, error) VALUES (?, ?, ?, ?)")
            .run(s.id, 'down', null, e.message);
          console.log(`[${new Date().toISOString()}] ${s.name}: DOWN (${e.message})`);
        }
      }
    } catch(_) {}
    await new Promise(r => setTimeout(r, Number(process.env.PING_INTERVAL) || 30000));
  }
}
loop();

srv.listen(PORT, '0.0.0.0', () => {
  console.log(`Website Pinger running on http://localhost:${PORT}`);
  console.log(`Login: admin / admin123`);
});
