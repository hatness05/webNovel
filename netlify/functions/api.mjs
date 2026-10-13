import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const store = () => getStore({ name: "hatness", consistency: "strong" });
const json = (d, s = 200) =>
  new Response(JSON.stringify(d), {
    status: s,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

// ---------- Auth (password lives only in the ADMIN_PASSWORD env variable) ----------
const secret = () => process.env.TOKEN_SECRET || process.env.ADMIN_PASSWORD || "";
const sign = (exp) => crypto.createHmac("sha256", secret()).update(String(exp)).digest("hex");
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
const makeToken = () => { const exp = Date.now() + 7 * 864e5; return exp + "." + sign(exp); };
function isAuth(req) {
  if (!secret()) return false;
  const [exp, sig] = (req.headers.get("authorization") || "").replace("Bearer ", "").split(".");
  if (!exp || !sig || +exp < Date.now()) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(exp));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const ID = /^[a-z0-9-]{1,80}$/;
const str = (v, max) => String(v ?? "").slice(0, max);
const getIndex = async (s) => (await s.get("index", { type: "json" })) || [];

export default async (req) => {
  const url = new URL(req.url);
  const route = url.pathname.replace(/^\/api/, "");
  const m = req.method;
  const q = url.searchParams;
  const s = store();

  // ---------- Public ----------
  if (m === "GET" && route === "/novels") return json(await getIndex(s));

  if (m === "GET" && route === "/chapter") {
    const c = await s.get(`ch:${q.get("novel")}:${q.get("n")}`, { type: "json" });
    return c ? json(c) : json({ error: "Chapter not found" }, 404);
  }

  if (m === "GET" && route === "/cover") {
    const d = await s.get(`cover:${q.get("id")}`, { type: "text" });
    const mm = d && d.match(/^data:(image\/[\w+.-]+);base64,(.+)$/);
    if (!mm) return new Response("Not found", { status: 404 });
    return new Response(Buffer.from(mm[2], "base64"), {
      headers: { "content-type": mm[1], "cache-control": "public, max-age=31536000, immutable" },
    });
  }

  if (m === "POST" && route === "/login") {
    const { password } = await req.json().catch(() => ({}));
    const ok = secret() && crypto.timingSafeEqual(sha(password), sha(process.env.ADMIN_PASSWORD));
    if (!ok) { await new Promise((r) => setTimeout(r, 800)); return json({ error: "Wrong password" }, 401); }
    return json({ token: makeToken() });
  }

  // ---------- Admin only ----------
  if (!isAuth(req)) return json({ error: "Unauthorized" }, 401);

  if (m === "PUT" && route === "/novel") {
    const b = await req.json().catch(() => ({}));
    if (!ID.test(b.id || "") || !String(b.title || "").trim()) return json({ error: "Invalid data" }, 400);
    const idx = await getIndex(s);
    const old = idx.find((n) => n.id === b.id);
    let cover = str(b.cover, 500);
    if (b.coverData) {
      if (!/^data:image\/[\w+.-]+;base64,/.test(b.coverData) || b.coverData.length > 2e6)
        return json({ error: "Invalid cover image" }, 400);
      await s.set(`cover:${b.id}`, b.coverData);
      cover = `/api/cover?id=${b.id}&v=${Date.now()}`;
    } else if (!/^(https?:\/\/|\/api\/cover\?)/.test(cover)) cover = "";
    const novel = {
      id: b.id, title: str(b.title, 200), author: str(b.author, 100) || "Anonymous",
      status: str(b.status, 30) || "Ongoing", synopsis: str(b.synopsis, 3000), cover,
      chapters: old ? old.chapters : [],
    };
    await s.setJSON("index", old ? idx.map((n) => (n.id === b.id ? novel : n)) : [...idx, novel]);
    return json({ ok: true });
  }

  if (m === "DELETE" && route === "/novel") {
    const id = q.get("id");
    const idx = await getIndex(s);
    const n = idx.find((x) => x.id === id);
    if (!n) return json({ error: "Not found" }, 404);
    await Promise.all(n.chapters.map((c) => s.delete(`ch:${id}:${c.number}`)));
    await s.delete(`cover:${id}`);
    await s.setJSON("index", idx.filter((x) => x.id !== id));
    return json({ ok: true });
  }

  if (m === "PUT" && route === "/chapter") {
    const b = await req.json().catch(() => ({}));
    const num = parseInt(b.number, 10);
    const content = String(b.content || "");
    if (!num || num < 1 || num > 99999 || !content.trim() || content.length > 500000)
      return json({ error: "Invalid chapter" }, 400);
    const idx = await getIndex(s);
    const n = idx.find((x) => x.id === b.novel);
    if (!n) return json({ error: "Novel not found" }, 404);
    const title = str(b.title, 200);
    await s.setJSON(`ch:${n.id}:${num}`, { number: num, title, content });
    n.chapters = [...n.chapters.filter((c) => c.number !== num), { number: num, title }].sort((a, b) => a.number - b.number);
    await s.setJSON("index", idx);
    return json({ ok: true });
  }

  if (m === "DELETE" && route === "/chapter") {
    const id = q.get("novel"), num = parseInt(q.get("n"), 10);
    const idx = await getIndex(s);
    const n = idx.find((x) => x.id === id);
    if (!n) return json({ error: "Not found" }, 404);
    await s.delete(`ch:${id}:${num}`);
    n.chapters = n.chapters.filter((c) => c.number !== num);
    await s.setJSON("index", idx);
    return json({ ok: true });
  }

  return json({ error: "Not found" }, 404);
};
