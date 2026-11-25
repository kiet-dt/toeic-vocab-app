// Backend: tài khoản + từ vựng riêng của từng người, lưu trong Netlify Blobs.
//   POST   /api/register   {username, password}        -> tạo tài khoản, trả về token
//   POST   /api/login      {username, password}        -> trả về token
//   POST   /api/reset      {username, newPassword}     -> đặt lại mật khẩu (chỉ cần tên tài khoản)
//   GET    /api/words      (token)                     -> từ của riêng người đăng nhập
//   POST   /api/words      (token) {section, en, vi}   -> thêm từ
//   DELETE /api/words?id=  (token)                     -> xóa từ
import { getStore } from "@netlify/blobs";
import { createHmac, randomBytes, randomUUID, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);

const SECTIONS = ["reading", "listening"];
const USER_RE = /^[a-z0-9._-]{3,30}$/;
const MAX_EN = 100;
const MAX_VI = 500;
const MAX_WORDS = 3000;
const TOKEN_DAYS = 30;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const normUser = (s) => String(s || "").trim().toLowerCase();
const normWord = (s) => String(s).toLowerCase().replace(/\s+/g, " ").trim();

// ---------- mật khẩu ----------
async function hashPassword(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : randomBytes(16);
  const hash = await scryptAsync(String(password), salt, 64);
  return { salt: salt.toString("hex"), hash: hash.toString("hex") };
}

async function passwordMatches(user, password) {
  const { hash } = await hashPassword(password, user.salt);
  const a = Buffer.from(hash, "hex");
  const b = Buffer.from(user.hash, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

function validPassword(p) {
  return typeof p === "string" && p.length >= 6 && p.length <= 100;
}

// ---------- token đăng nhập ----------
async function getSecret(store) {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  let s = await store.get("secret");
  if (!s) {
    await store.set("secret", randomBytes(32).toString("hex"));
    s = await store.get("secret");
  }
  return s;
}

const sig = (body, secret) => createHmac("sha256", secret).update(body).digest("base64url");

function signToken(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${body}.${sig(body, secret)}`;
}

function verifyToken(token, secret) {
  const [body, given] = String(token || "").split(".");
  if (!body || !given) return null;
  const expected = sig(body, secret);
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString());
    return payload.exp > Date.now() ? payload : null;
  } catch {
    return null;
  }
}

async function makeToken(store, user) {
  const secret = await getSecret(store);
  return signToken(
    { u: user.username, v: user.tv, exp: Date.now() + TOKEN_DAYS * 86400000 },
    secret
  );
}

async function authenticate(req, store) {
  const m = /^Bearer (.+)$/.exec(req.headers.get("authorization") || "");
  if (!m) return null;
  const payload = verifyToken(m[1], await getSecret(store));
  if (!payload) return null;
  const user = await store.get(`user:${payload.u}`, { type: "json" });
  if (!user || user.tv !== payload.v) return null; // đã đổi mật khẩu -> token cũ hết hiệu lực
  return user;
}

// ---------- từ vựng ----------
async function readWords(store, username) {
  const d = (await store.get(`words:${username}`, { type: "json" })) || {};
  return {
    reading: Array.isArray(d.reading) ? d.reading : [],
    listening: Array.isArray(d.listening) ? d.listening : [],
  };
}

async function readBody(req) {
  try {
    const b = await req.json();
    return b && typeof b === "object" ? b : {};
  } catch {
    return {};
  }
}

export default async (req) => {
  const store = getStore({ name: "toeic-vocab", consistency: "strong" });
  const path = new URL(req.url).pathname.replace(/\/+$/, "");
  const route = `${req.method} ${path}`;

  // ----- đăng ký -----
  if (route === "POST /api/register") {
    const b = await readBody(req);
    const username = normUser(b.username);
    if (!USER_RE.test(username)) {
      return json({ error: "Tên tài khoản gồm 3-30 ký tự: chữ không dấu, số, dấu . _ -" }, 400);
    }
    if (!validPassword(b.password)) {
      return json({ error: "Mật khẩu cần từ 6 đến 100 ký tự." }, 400);
    }
    if (await store.get(`user:${username}`)) {
      return json({ error: "Tên tài khoản này đã có người dùng." }, 409);
    }
    const { salt, hash } = await hashPassword(b.password);
    const user = { username, salt, hash, tv: 1, createdAt: new Date().toISOString() };
    await store.setJSON(`user:${username}`, user);
    return json({ token: await makeToken(store, user), username }, 201);
  }

  // ----- đăng nhập -----
  if (route === "POST /api/login") {
    const b = await readBody(req);
    const username = normUser(b.username);
    const user = USER_RE.test(username) ? await store.get(`user:${username}`, { type: "json" }) : null;
    const ok = user && validPassword(b.password) && (await passwordMatches(user, b.password));
    if (!ok) return json({ error: "Sai tên tài khoản hoặc mật khẩu." }, 401);
    return json({ token: await makeToken(store, user), username: user.username });
  }

  // ----- quên mật khẩu: chỉ cần tên tài khoản + mật khẩu mới -----
  if (route === "POST /api/reset") {
    const b = await readBody(req);
    const username = normUser(b.username);
    if (!validPassword(b.newPassword)) {
      return json({ error: "Mật khẩu mới cần từ 6 đến 100 ký tự." }, 400);
    }
    const user = USER_RE.test(username) ? await store.get(`user:${username}`, { type: "json" }) : null;
    if (!user) return json({ error: "Không tìm thấy tài khoản này." }, 404);
    const { salt, hash } = await hashPassword(b.newPassword);
    await store.setJSON(`user:${username}`, { ...user, salt, hash, tv: user.tv + 1 });
    return json({ ok: true });
  }

  // ----- từ vựng (cần đăng nhập) -----
  if (path === "/api/words") {
    const user = await authenticate(req, store);
    if (!user) return json({ error: "Bạn cần đăng nhập." }, 401);

    if (req.method === "GET") {
      return json(await readWords(store, user.username));
    }

    if (req.method === "POST") {
      const b = await readBody(req);
      const section = b.section;
      const en = String(b.en || "").trim();
      const vi = String(b.vi || "").trim();
      if (!SECTIONS.includes(section)) return json({ error: "Mục không hợp lệ." }, 400);
      if (!en || !vi) return json({ error: "Thiếu từ tiếng Anh hoặc nghĩa." }, 400);
      if (en.length > MAX_EN) return json({ error: `Từ tiếng Anh tối đa ${MAX_EN} ký tự.` }, 400);
      if (vi.length > MAX_VI) return json({ error: `Nghĩa tối đa ${MAX_VI} ký tự.` }, 400);

      const all = await readWords(store, user.username);
      if (all.reading.length + all.listening.length >= MAX_WORDS) {
        return json({ error: `Mỗi tài khoản tối đa ${MAX_WORDS} từ tự thêm.` }, 400);
      }
      if (all[section].some((w) => normWord(w.en) === normWord(en))) {
        return json({ error: "Từ này đã có trong danh sách của bạn." }, 409);
      }
      const item = { id: randomUUID(), en, vi, createdAt: new Date().toISOString() };
      all[section].push(item);
      await store.setJSON(`words:${user.username}`, all);
      return json({ item, section }, 201);
    }

    if (req.method === "DELETE") {
      const id = new URL(req.url).searchParams.get("id");
      if (!id) return json({ error: "Thiếu id." }, 400);
      const all = await readWords(store, user.username);
      let found = false;
      for (const s of SECTIONS) {
        const before = all[s].length;
        all[s] = all[s].filter((w) => w.id !== id);
        if (all[s].length !== before) found = true;
      }
      if (!found) return json({ error: "Không tìm thấy từ này." }, 404);
      await store.setJSON(`words:${user.username}`, all);
      return json({ ok: true });
    }
  }

  return json({ error: "Not found" }, 404);
};

export const config = { path: "/api/*" };
