// Telegram admin bot for smartdns, deployed as a Cloudflare Worker. It holds
// the Telegram token and admin allowlist, and applies changes to the VPS via
// its token-protected admin API (see internal/adminapi on the server).

const STATE_TTL_SECONDS = 600;
const API_TIMEOUT_MS = 8000;

const MENU_TEXT = "چی می‌خوای اضافه کنی؟";
const ASK_DOMAIN = "نام دامنه رو بفرست، مثلاً example.com";
const ASK_IP = "آی‌پی یا CIDR رو بفرست، مثلاً 203.0.113.5 یا 203.0.113.0/24";

export default {
  async fetch(request, env, ctx) {
    if (request.method !== "POST") {
      return new Response("not found", { status: 404 });
    }
    const secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
    if (!secret || !timingSafeEqual(secret, env.WEBHOOK_SECRET)) {
      return new Response("forbidden", { status: 403 });
    }

    let update;
    try {
      update = await request.json();
    } catch {
      return new Response("ok");
    }

    // Answer Telegram immediately; slow VPS calls must not make Telegram
    // time out and redeliver the same update.
    ctx.waitUntil(
      handleUpdate(update, env).catch((err) =>
        console.log("handler error:", err && err.message),
      ),
    );
    return new Response("ok");
  },
};

async function handleUpdate(update, env) {
  if (update.callback_query) {
    return handleCallback(update.callback_query, env);
  }
  const msg = update.message;
  if (!msg || typeof msg.text !== "string") return;
  // Only act in 1:1 chats; admin identity is per user ID.
  if (msg.chat.type !== "private") return;

  const userId = String(msg.from.id);
  if (!isAdmin(userId, env)) {
    console.log("rejected unauthorized user", userId);
    return reply(env, msg.chat.id, "دسترسی نداری.");
  }

  const text = msg.text.trim();
  if (!text.startsWith("/")) {
    if (await consumeState(env, userId, msg.chat.id, text)) return;
    return sendMenu(env, msg.chat.id);
  }

  const [rawCmd, ...rest] = text.split(/\s+/);
  const cmd = rawCmd.split("@")[0]; // strip "@botname" suffix in groups
  const arg = rest[0] || "";

  switch (cmd) {
    case "/add_domain":
      if (!arg) return startFlow(env, userId, msg.chat.id, "domain");
      await clearState(env, userId);
      return addDomain(env, msg.chat.id, arg);
    case "/add_ip":
      if (!arg) return startFlow(env, userId, msg.chat.id, "ip");
      await clearState(env, userId);
      return addIP(env, msg.chat.id, arg);
    case "/list":
      await clearState(env, userId);
      return listEntries(env, msg.chat.id);
    case "/cancel":
      await clearState(env, userId);
      return reply(env, msg.chat.id, "لغو شد.");
    case "/start":
    case "/help":
    case "/menu":
      await clearState(env, userId);
      return sendMenu(env, msg.chat.id);
    default:
      return sendMenu(env, msg.chat.id);
  }
}

async function handleCallback(cq, env) {
  await telegram(env, "answerCallbackQuery", { callback_query_id: cq.id });
  if (!cq.message) return;
  const userId = String(cq.from.id);
  const chatId = cq.message.chat.id;
  if (!isAdmin(userId, env)) {
    console.log("rejected unauthorized button press", userId);
    return;
  }
  const data = String(cq.data || "");
  if (/^rm:\d+$/.test(data)) {
    return removeByIndex(env, userId, chatId, Number(data.slice(3)));
  }
  switch (data) {
    case "add_domain":
      return startFlow(env, userId, chatId, "domain");
    case "add_ip":
      return startFlow(env, userId, chatId, "ip");
    case "rm_domain":
      return showRemovePicker(env, chatId, userId, "domain");
    case "rm_ip":
      return showRemovePicker(env, chatId, userId, "ip");
    case "list":
      await clearState(env, userId);
      return listEntries(env, chatId);
  }
}

// The picked list is stored in KV and buttons refer to it by index, because
// Telegram limits callback_data to 64 bytes and domains can be longer.
const PICK_LIMIT = 50;

async function showRemovePicker(env, chatId, userId, kind) {
  const res = await callAPI(env, "GET", listPath(kind));
  if (!res.ok) return reply(env, chatId, "خطا در خواندن لیست از سرور.");
  const all = res.body.entries || [];
  if (all.length === 0) return reply(env, chatId, "لیست خالیه.");
  const items = all.slice(0, PICK_LIMIT);
  await env.STATE.put(pickKey(userId), JSON.stringify({ kind, items }), {
    expirationTtl: STATE_TTL_SECONDS,
  });
  const rows = items.map((v, i) => [{ text: `🗑 ${v}`, callback_data: `rm:${i}` }]);
  const note = all.length > PICK_LIMIT ? `\n(فقط ${PICK_LIMIT} مورد اول نشون داده شد)` : "";
  return telegram(env, "sendMessage", {
    chat_id: chatId,
    text: `کدوم ${kind === "domain" ? "دامنه" : "آی‌پی"} رو حذف کنم؟${note}`,
    reply_markup: { inline_keyboard: rows },
  });
}

async function removeByIndex(env, userId, chatId, index) {
  const raw = await env.STATE.get(pickKey(userId));
  if (!raw) return reply(env, chatId, "این لیست منقضی شده؛ دوباره از منو انتخاب کن.");
  const { kind, items } = JSON.parse(raw);
  const value = items[index];
  if (value === undefined) return reply(env, chatId, "این مورد معتبر نیست؛ دوباره از منو انتخاب کن.");
  await env.STATE.delete(pickKey(userId));

  const res = await callAPI(env, "DELETE", listPath(kind), { value });
  if (!res.ok) {
    return reply(env, chatId, `حذف نشد (${res.status || "بدون پاسخ"}): ${res.error || ""}`.trim());
  }
  if (!res.body.removed) return reply(env, chatId, `این مورد دیگه توی لیست نیست: ${value}`);
  return reply(env, chatId, `🗑 حذف و اعمال شد: ${value}`);
}

function listPath(kind) {
  return kind === "domain" ? "/v1/domains" : "/v1/ips";
}

function pickKey(userId) {
  return `pick:${userId}`;
}

async function startFlow(env, userId, chatId, kind) {
  await env.STATE.put(stateKey(userId), kind, { expirationTtl: STATE_TTL_SECONDS });
  return reply(env, chatId, kind === "domain" ? ASK_DOMAIN : ASK_IP);
}

// Returns true if text was consumed by an in-progress flow. Invalid input
// keeps the flow open so the admin can retry without pressing the button again.
async function consumeState(env, userId, chatId, text) {
  const kind = await env.STATE.get(stateKey(userId));
  if (!kind) return false;
  const done = kind === "domain"
    ? await addDomain(env, chatId, text)
    : await addIP(env, chatId, text);
  if (done) await clearState(env, userId);
  return true;
}

// Each add* returns true when the flow is finished (success, already present,
// or reload failure) and false only when the input was rejected.
async function addDomain(env, chatId, value) {
  const res = await callAPI(env, "POST", "/v1/domains", { value: value.trim() });
  if (res.status === 400) {
    await reply(env, chatId, `❌ ${res.error}\nدوباره بفرست یا /cancel بزن.`);
    return false;
  }
  return finishAdd(env, chatId, res, value, "دامنه");
}

async function addIP(env, chatId, value) {
  const res = await callAPI(env, "POST", "/v1/ips", { value: value.trim() });
  if (res.status === 400) {
    await reply(env, chatId, `❌ ${res.error}\nدوباره بفرست یا /cancel بزن.`);
    return false;
  }
  return finishAdd(env, chatId, res, value, "آی‌پی");
}

async function finishAdd(env, chatId, res, value, label) {
  if (res.status === 500) {
    await reply(env, chatId, `${label} ذخیره شد ولی اعمال (reload) شکست خورد: ${res.error}`);
    return true;
  }
  if (res.status === 401) {
    await reply(env, chatId, "❌ احراز هویت با سرور شکست خورد: ADMIN_TOKEN توی Worker با توکن VPS یکی نیست.");
    return false;
  }
  if (!res.ok) {
    await reply(env, chatId, `خطای سرور (${res.status || "بدون پاسخ"}). کمی بعد دوباره امتحان کن؛ این ${label} هنوز ثبت نشده.`);
    return false;
  }
  if (!res.body.added) {
    await reply(env, chatId, `این ${label} از قبل توی لیست هست: ${value}`);
    return true;
  }
  await reply(env, chatId, `✅ ${label} اضافه و اعمال شد: ${value}`);
  return true;
}

async function listEntries(env, chatId) {
  const [d, i] = await Promise.all([
    callAPI(env, "GET", "/v1/domains"),
    callAPI(env, "GET", "/v1/ips"),
  ]);
  if (!d.ok || !i.ok) {
    return reply(env, chatId, "خطا در خواندن لیست از سرور.");
  }
  const domains = d.body.entries || [];
  const ips = i.body.entries || [];
  const text = `دامنه‌ها (${domains.length}):\n${domains.join("\n")}\n\nآی‌پی‌های مجاز (${ips.length}):\n${ips.join("\n")}`;
  // Telegram rejects messages over 4096 chars; keep well under that.
  const MAX = 3900;
  return reply(env, chatId, text.length > MAX ? text.slice(0, MAX) + "\n…(ادامه کوتاه شد)" : text);
}

// callAPI always resolves to {ok, status, body?, error?} and never throws,
// so a VPS outage can't crash the webhook handler.
async function callAPI(env, method, path, payload) {
  let resp;
  try {
    resp = await fetch(env.API_BASE + path, {
      method,
      headers: {
        Authorization: `Bearer ${env.ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: payload ? JSON.stringify(payload) : undefined,
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
    });
  } catch (err) {
    return { ok: false, status: 0, error: "سرور در دسترس نیست" };
  }
  let body = {};
  try {
    body = await resp.json();
  } catch {
    body = {};
  }
  if (!resp.ok) {
    return { ok: false, status: resp.status, error: body.error || "خطا" };
  }
  return { ok: true, status: resp.status, body };
}

async function sendMenu(env, chatId) {
  return telegram(env, "sendMessage", {
    chat_id: chatId,
    text: MENU_TEXT,
    reply_markup: {
      inline_keyboard: [
        [{ text: "➕ افزودن دامنه", callback_data: "add_domain" }],
        [{ text: "➕ افزودن آی‌پی", callback_data: "add_ip" }],
        [{ text: "🗑 حذف دامنه", callback_data: "rm_domain" }],
        [{ text: "🗑 حذف آی‌پی", callback_data: "rm_ip" }],
        [{ text: "📋 لیست فعلی", callback_data: "list" }],
      ],
    },
  });
}

function reply(env, chatId, text) {
  return telegram(env, "sendMessage", { chat_id: chatId, text });
}

async function telegram(env, method, payload) {
  try {
    const resp = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
    });
    if (!resp.ok) {
      console.log(`telegram ${method} rejected: ${resp.status} ${await resp.text()}`);
    }
  } catch (err) {
    console.log(`telegram ${method} failed:`, err && err.message);
  }
}

function isAdmin(userId, env) {
  return (env.ADMIN_IDS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .includes(userId);
}

function stateKey(userId) {
  return `state:${userId}`;
}

function clearState(env, userId) {
  return env.STATE.delete(stateKey(userId));
}

// Constant-time string compare so the webhook secret can't be guessed by
// timing differences in an early-exit comparison.
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
