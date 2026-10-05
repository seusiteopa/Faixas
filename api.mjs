import { getStore } from "@netlify/blobs";
import { createHmac, timingSafeEqual, randomUUID } from "node:crypto";
import dns from "node:dns/promises";
import net from "node:net";

export const config = { path: "/api/*" };

const S = () => getStore("faixas");
const J = (d, s = 200, h = {}) =>
  new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store", ...h } });
const load = async () => (await S().get("data", { type: "json" })) || { rev: 0, links: [] };
const save = async (d) => { d.rev++; await S().setJSON("data", d); return d; };
const sig = (p) => createHmac("sha256", process.env.TOKEN_SECRET || "").update(p).digest("base64url");
const mk = () => { const p = String(Date.now() + 6048e5); return p + "." + sig(p); };
const same = (a, b) => { a = Buffer.from(a); b = Buffer.from(b); return a.length === b.length && timingSafeEqual(a, b); };
const valid = (t) => { const [p, s] = (t || "").split("."); return !!(p && s && same(sig(p), s) && +p > Date.now()); };
const priv = (ip) => net.isIPv4(ip)
  ? /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip)
  : /^(::1?$|f[cd]|fe[89ab]|::ffff:)/i.test(ip);
const dec = (s) => s.replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").trim();

async function page(u) {
  for (let i = 0; i < 4; i++) {
    const x = new URL(u);
    if (!/^https?:$/.test(x.protocol)) throw "bloq";
    const ips = net.isIP(x.hostname) ? [{ address: x.hostname }] : await dns.lookup(x.hostname, { all: true });
    if (ips.some((a) => priv(a.address))) throw "bloq";
    const r = await fetch(x, { redirect: "manual", signal: AbortSignal.timeout(6000), headers: { accept: "text/html", "user-agent": "Mozilla/5.0 (compatible; FaixasBot/1.0)" } });
    const loc = r.headers.get("location");
    if (r.status >= 300 && r.status < 400 && loc) { u = new URL(loc, x).href; continue; }
    if (!r.ok || !/html/.test(r.headers.get("content-type") || "")) throw "inacc";
    const rd = r.body.getReader(), td = new TextDecoder();
    let t = "", n = 0;
    while (n < 1e6) {
      const { done, value } = await rd.read();
      if (done) break;
      n += value.length; t += td.decode(value, { stream: true });
      if (/<\/head>/i.test(t)) break;
    }
    rd.cancel().catch(() => {});
    return { html: t, base: x };
  }
  throw "inacc";
}

const https = (u, base) => { try { const i = new URL(u, base); if (!/^https?:$/.test(i.protocol)) return; i.protocol = "https:"; return i.href; } catch {} };

function vid(m, base) {
  const x = base, h = x.hostname.replace(/^(www|m)\./, "");
  let id = h === "youtu.be" ? x.pathname.slice(1).split("/")[0]
    : /(^|\.)youtube\.com$/.test(h) ? x.searchParams.get("v") || /^\/(?:shorts|embed|live)\/([\w-]{6,})/.exec(x.pathname)?.[1] : null;
  if (id && /^[\w-]{6,15}$/.test(id)) return { k: "yt", id };
  id = h === "vimeo.com" ? /^\/(?:[\w-]+\/)*(\d{5,})/.exec(x.pathname)?.[1] : null;
  if (id) return { k: "vm", id };
  const f = https(m["video:secure_url"] || m["video:url"] || m.video, base);
  if (f && (/\.(mp4|webm)$/i.test(new URL(f).pathname) || /^video\/(mp4|webm)/.test(m["video:type"] || ""))) return { k: "file", src: f };
}

function og(html, base) {
  const m = {};
  for (const t of html.match(/<meta\b[^>]*>/gi) || []) {
    const k = /(?:property|name)=["']og:(title|description|image|video(?::secure_url|:url|:type)?)["']/i.exec(t)?.[1];
    const c = /content=["']([^"']*)["']/i.exec(t)?.[1];
    if (k && c && !m[k]) m[k] = dec(c);
  }
  return { title: m.title, description: m.description || "", image: m.image && https(m.image, base), video: vid(m, base) };
}

async function info(raw) {
  let x;
  try { x = new URL(raw); if (!/^https?:$/.test(x.protocol)) throw 0; } catch { throw { e: "url" }; }
  let pg;
  try { pg = await page(x.href); } catch (e) { throw { e: e === "bloq" ? "bloq" : e?.name === "TimeoutError" ? "lento" : "inacc" }; }
  const o = og(pg.html, pg.base);
  const falta = [!o.title && "o título", !(o.image || o.video) && "a imagem"].filter(Boolean).join(" e ");
  if (falta) throw { e: "og", falta };
  return o;
}

export default async (req) => {
  const p = new URL(req.url).pathname.replace(/^\/api/, ""), m = req.method;
  try {
    if (!process.env.ADMIN_PASSWORD || !process.env.TOKEN_SECRET) return J({ e: "srv" }, 500);
    if (p === "/links" && m === "GET") {
      const d = await load();
      return J(d.links.filter((l) => l.visible).map(({ id, url, title, description, image, video }) => ({ id, url, title, description, image, video })), 200,
        { "cache-control": "public, max-age=0, s-maxage=10" });
    }
    const b = m === "POST" || m === "PUT" ? await req.json().catch(() => ({})) : {};
    if (p === "/login" && m === "POST") {
      const s = S(), k = "rl:" + (req.headers.get("x-nf-client-connection-ip") || "x");
      const r = (await s.get(k, { type: "json" })) || { n: 0, t: 0 }, fresh = Date.now() - r.t < 9e5;
      if (fresh && r.n >= 5) return J({ e: "rate" }, 429);
      if (!same(sig(String(b.senha || "")), sig(process.env.ADMIN_PASSWORD))) {
        await s.setJSON(k, { n: fresh ? r.n + 1 : 1, t: Date.now() });
        return J({ e: "senha" }, 401);
      }
      await s.delete(k);
      return J({ token: mk() });
    }
    if (!valid((req.headers.get("authorization") || "").slice(7))) return J({ e: "auth" }, 401);
    if (p === "/preview" && m === "POST") return J(await info(b.url));
    const d = await load();
    if (p === "/admin/links") return J(d);
    if (p === "/links" && m === "POST") {
      const o = await info(b.url), url = new URL(b.url).href;
      if (d.links.some((l) => l.url === url)) throw { e: "dup" };
      d.links.push({ id: randomUUID(), url, ...o, visible: true, createdAt: Date.now() });
      return J(await save(d));
    }
    if (p === "/order" && m === "PUT") {
      const by = new Map(d.links.map((l) => [l.id, l]));
      if (b.rev !== d.rev) throw { e: "rev" };
      if (!Array.isArray(b.ids) || b.ids.length !== by.size || !b.ids.every((i) => by.has(i))) throw { e: "ids" };
      d.links = b.ids.map((i) => by.get(i));
      return J(await save(d));
    }
    const q = /^\/links\/([\w-]+)(?:\/(toggle|refresh))?$/.exec(p);
    if (q) {
      const i = d.links.findIndex((l) => l.id === q[1]);
      if (i < 0) throw { e: "nf" };
      const l = d.links[i];
      if (m === "DELETE" && !q[2]) d.links.splice(i, 1);
      else if (m === "POST" && q[2] === "toggle") l.visible = !l.visible;
      else if (m === "POST" && q[2] === "refresh") Object.assign(l, await info(l.url), { updatedAt: Date.now() });
      else return J({ e: "nf" }, 404);
      return J(await save(d));
    }
    return J({ e: "nf" }, 404);
  } catch (x) {
    return x?.e ? J(x, 400) : J({ e: "srv" }, 500);
  }
};
