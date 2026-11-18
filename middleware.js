// Passwortschutz nur für /test/* (Vercel Routing Middleware).
// Das Passwort steht NICHT im Code, sondern in der Vercel-Umgebungsvariable TEST_PASSWORD.
import { next } from '@vercel/functions';

export const config = { matcher: ['/test', '/test/:path*'] };

const COOKIE = 'test_auth';
const SALT = 'mathe-tools-test-v1';

async function hash(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function getCookie(req, name) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return m ? m[1] : '';
}

function page(msg) {
  const html = `<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Test-Seite gesperrt</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;font-family:system-ui,Segoe UI,sans-serif;background:#0f172a;color:#e2e8f0}
form{width:100%;max-width:340px;background:#1e293b;border:1px solid #334155;border-radius:14px;padding:26px;display:flex;flex-direction:column;gap:12px}
h1{margin:0;font-size:1.25rem}
p{margin:0;color:#94a3b8;font-size:.9rem}
input{padding:11px 12px;border-radius:8px;border:1px solid #475569;background:#0f172a;color:#e2e8f0;font-size:1rem}
input:focus{outline:2px solid #38bdf8;border-color:#38bdf8}
button{padding:11px;border:0;border-radius:8px;background:#38bdf8;color:#0f172a;font-weight:700;font-size:1rem;cursor:pointer}
.err{color:#fca5a5;font-size:.9rem}
</style></head><body>
<form method="POST">
<h1>🔒 Test-Seite</h1>
<p>Diese Seite ist nur für die Lehrperson. Bitte Passwort eingeben.</p>
<input type="password" name="password" placeholder="Passwort" autocomplete="current-password" autofocus required>
${msg ? '<div class="err">' + msg + '</div>' : ''}
<button type="submit">Öffnen</button>
</form></body></html>`;
  return new Response(html, {
    status: 401,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
  });
}

export default async function middleware(request) {
  const pw = process.env.TEST_PASSWORD;
  if (!pw) return page('Passwortschutz nicht eingerichtet (TEST_PASSWORD fehlt). Seite bleibt gesperrt.');

  const token = await hash(pw + ':' + SALT);

  if (getCookie(request, COOKIE) === token) return next();

  if (request.method === 'POST') {
    let given = '';
    try { given = String((await request.formData()).get('password') || ''); } catch (e) {}
    if (given && (await hash(given + ':' + SALT)) === token) {
      return new Response(null, {
        status: 303,
        headers: {
          Location: new URL(request.url).pathname,
          'Set-Cookie': `${COOKIE}=${token}; Path=/test; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax`,
          'cache-control': 'no-store',
        },
      });
    }
    return page('Falsches Passwort.');
  }

  return page('');
}
