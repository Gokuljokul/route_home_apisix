const crypto = require("node:crypto");
const http = require("node:http");

const username = process.env.APISIX_AUTH_USER;
const password = process.env.APISIX_AUTH_PASSWORD;
if (!username || !password) {
  throw new Error("APISIX_AUTH_USER and APISIX_AUTH_PASSWORD must be set");
}

const sessionLifetimeMs = 12 * 60 * 60 * 1000;
const sessions = new Map();
const cookieName = "portal_session";

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[char]);
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    ...headers,
  });
  res.end(body);
}

function cookieValue(req) {
  const cookies = req.headers.cookie || "";
  const match = cookies.match(/(?:^|;\s*)portal_session=([a-f0-9]+)/);
  return match ? match[1] : null;
}

function sessionFor(req) {
  const token = cookieValue(req);
  if (!token) return null;
  const expiresAt = sessions.get(token);
  if (!expiresAt) return null;
  if (expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return token;
}

function loginPage(error = "") {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in</title>
<style>
:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#101827;color:#eef2ff}main{width:min(24rem,calc(100% - 3rem));padding:2rem;border:1px solid #34445f;border-radius:.75rem;background:#19253a}h1{margin-top:0}label{display:block;margin:.9rem 0 .25rem}input{box-sizing:border-box;width:100%;padding:.7rem;border:1px solid #52627c;border-radius:.4rem;font:inherit}button{margin-top:1.25rem;width:100%;padding:.75rem;border:0;border-radius:.4rem;background:#8ab4ff;color:#101827;font:inherit;font-weight:700;cursor:pointer}.error{color:#ffb4ab}
</style></head><body><main><h1>Sign in</h1>${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
<form action="/login" method="post"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Sign in</button></form></main></body></html>`;
}

function homePage() {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Home</title>
<style>
:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#101827;color:#eef2ff}main{width:min(32rem,calc(100% - 3rem))}h1{margin-bottom:.25rem}p{color:#aab6ca}nav{display:grid;gap:.75rem;margin-top:2rem}a{display:block;padding:1rem 1.25rem;border:1px solid #34445f;border-radius:.75rem;color:inherit;text-decoration:none;background:#19253a}a:hover,a:focus-visible{border-color:#8ab4ff;outline:none}a span{display:block;color:#aab6ca;font-size:.9rem}.future{opacity:.65}.bar{display:flex;justify-content:space-between;align-items:center}.bar form{margin:0}.bar button{padding:.5rem .75rem;border:1px solid #52627c;border-radius:.4rem;background:#19253a;color:inherit;font:inherit;cursor:pointer}
</style></head><body><main><div class="bar"><h1>Home</h1><form action="/logout" method="post"><button type="submit">Log out</button></form></div>
<p>Select a service to continue.</p><nav aria-label="Services"><a href="/ssh/">SSH terminal<span>Open the web terminal</span></a><a class="future" aria-disabled="true">More services<span>Additional menu items will be added here</span></a></nav></main></body></html>`;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");

  if (url.pathname === "/auth") {
    if (sessionFor(req)) {
      res.writeHead(200, { "Cache-Control": "no-store" });
      return res.end();
    }
    res.writeHead(401, { "Cache-Control": "no-store" });
    return res.end();
  }

  if (url.pathname === "/login" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 8192) req.destroy();
    });
    req.on("end", () => {
      const form = new URLSearchParams(body);
      const submittedUser = form.get("username") || "";
      const submittedPassword = form.get("password") || "";
      const validUser = submittedUser === username;
      const expected = Buffer.from(password);
      const actual = Buffer.from(submittedPassword);
      const validPassword = expected.length === actual.length
        && crypto.timingSafeEqual(expected, actual);

      if (!validUser || !validPassword) {
        return send(res, 401, loginPage("Invalid username or password."));
      }

      const token = crypto.randomBytes(32).toString("hex");
      sessions.set(token, Date.now() + sessionLifetimeMs);
      res.writeHead(303, {
        "Location": "/",
        "Cache-Control": "no-store",
        "Set-Cookie": `${cookieName}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${sessionLifetimeMs / 1000}`,
      });
      res.end();
    });
    return;
  }

  if (url.pathname === "/logout") {
    const token = cookieValue(req);
    if (token) sessions.delete(token);
    res.writeHead(303, {
      "Location": "/login",
      "Cache-Control": "no-store",
      "Set-Cookie": `${cookieName}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
    });
    return res.end();
  }

  if (url.pathname === "/login") {
    return send(res, 200, loginPage());
  }

  if (url.pathname === "/" && sessionFor(req)) {
    return send(res, 200, homePage());
  }

  if (url.pathname === "/") {
    return send(res, 200, loginPage());
  }

  res.writeHead(404, { "Cache-Control": "no-store" });
  res.end("Not found");
});

server.listen(3000, "0.0.0.0");
