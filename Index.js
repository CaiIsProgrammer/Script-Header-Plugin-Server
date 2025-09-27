// server.js
import express from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import 'dotenv/config';
// ====== CONFIG ======
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const PLUGIN_ASSET_ID = process.env.PLUGIN_ASSET_ID
const MODEL_PATH = process.env.MODEL_PATH
const AI_URL = `${process.env.AI_URL}${MODEL_PATH}`;
const PRIVATE_INSTRUCTION = process.env.PRIVATE_INSTRUCTION

// ====== APP SETUP ======
const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "500kb" })); // keep tight caps

import cors from 'cors';
app.use(cors({ origin: true, credentials: false }));

// ====== UTILITIES ======
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
const now = () => Date.now();

// In-memory cache (for repeated identical requests) and simple rate limits.
const CACHE = new Map(); // key -> { text, ts }
const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6h

function cacheGet(key) {
    const v = CACHE.get(key);
    if (!v) return null;
    if (now() - v.ts > CACHE_TTL_MS) {
        CACHE.delete(key);
        return null;
    }
    return v.text;
}
function cacheSet(key, text) {
    CACHE.set(key, { text, ts: now() });
}

const RL_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const RL_MAX_VERIFY = 60;            // /license/verify per IP
const RL_MAX_SUMMARIZE = 120;        // /summarize per userId
const RL_VERIFY = new Map();         // ip -> {count, start}
const RL_SUM = new Map();            // userId -> {count, start}

function rateLimit(map, key, max, windowMs) {
    const t = now();
    let rec = map.get(key);
    if (!rec || t - rec.start > windowMs) rec = { count: 0, start: t };
    rec.count++;
    map.set(key, rec);
    return rec.count <= max;
}

// ====== ROBLOX OWNERSHIP CHECK ======
async function userOwnsAsset_public(userId, assetId) {
    // Docs/shape can change; current public endpoint returns data array when owned.
    const url = `https://inventory.roblox.com/v1/users/${userId}/items/Asset/${assetId}`;
    const resp = await fetch(url, { method: "GET" });
    if (!resp.ok) return { ok: false, reason: `Inventory ${resp.status}` };
    const data = await resp.json().catch(() => null);
    const owned = Array.isArray(data?.data) && data.data.some((i) => Number(i.id) === Number(assetId));
    return { ok: true, owned };
}

// ====== JWT HELPERS ======
function issueJwt(payload, expiresIn = "2h") {
    return jwt.sign(payload, JWT_SECRET, { expiresIn });
}
function verifyJwt(token) {
    return jwt.verify(token, JWT_SECRET);
}

// ====== ROUTES ======

// POST /license/verify  { userId:number }
app.post("/license/verify", async (req, res) => {
    try {
        // Basic IP-based rate limiting
        const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() || req.socket.remoteAddress || "ip";
        if (!rateLimit(RL_VERIFY, ip, RL_MAX_VERIFY, RL_WINDOW_MS)) {
            return res.status(429).json({ ok: false, error: "Too many requests. Try later." });
        }

        const { userId } = req.body || {};
        if (!userId || !Number.isFinite(Number(userId)) || !PLUGIN_ASSET_ID) {
            return res.status(400).json({ ok: false, error: "Missing userId or server assetId not set." });
        }

        const check = await userOwnsAsset_public(Number(userId), PLUGIN_ASSET_ID);
        if (!check.ok) {
            return res.status(502).json({ ok: false, error: "Ownership check failed: " + check.reason });
        }
        if (!check.owned) {
            return res.status(403).json({ ok: false, error: "User does not own required asset." });
        }

        // Ownership confirmed — issue short-lived JWT bound to userId.
        const token = issueJwt({ uid: Number(userId) }, "2h");
        return res.json({ ok: true, token });
    } catch (e) {

        return res.status(500).json({ ok: false, error: String(e) });
    }
});

// POST /summarize
// Headers: Authorization: Bearer <jwt>
// Body: { filename:string, type:string, contents:string, apiKey:string, pluginVersion?:string }
app.post("/summarize", async (req, res) => {
    try {
        const auth = req.headers.authorization || "";
        if (!auth.startsWith("Bearer ")) {
            return res.status(401).json({ ok: false, error: "Missing bearer token" });
        }
        let claims;
        try {
            claims = verifyJwt(auth.slice(7));
        } catch {
            return res.status(401).json({ ok: false, error: "Invalid/expired token" });
        }
        const userId = claims.uid;
        if (!userId) return res.status(401).json({ ok: false, error: "Bad token payload" });

        // Per-user rate limit
        if (!rateLimit(RL_SUM, String(userId), RL_MAX_SUMMARIZE, RL_WINDOW_MS)) {
            return res.status(429).json({ ok: false, error: "Rate limit exceeded. Try later." });
        }

        const { filename, type, contents, apiKey, pluginVersion } = req.body || {};
        if (!filename || !contents || !apiKey) {
            return res.status(400).json({ ok: false, error: "Missing filename/contents/apiKey" });
        }
        if (typeof contents !== "string" || contents.length === 0) {
            return res.status(400).json({ ok: false, error: "Empty contents" });
        }

        // Deduplicate repeated requests (saves buyer quota)
        const cacheKey = sha256(JSON.stringify({ filename, type: type || "", contents, model: MODEL_PATH, instr: PRIVATE_INSTRUCTION }));
        const cached = cacheGet(cacheKey);
        if (cached) {
            const wm = `\n--[[\n  Generated by: Script Tools v${pluginVersion || "1.0.0"}\n  Owner: UserId ${userId}\n  Timestamp: ${new Date().toISOString()}\n]]\n`;
            return res.json({ ok: true, headerComment: cached + wm, cached: true });
        }

        const var1 = process.env.VAR1
        const body = buildAICall([{ [var1]: PRIVATE_INSTRUCTION }, { [var1]: filename }, { [var1]: contents }])
        console.log({ [var1]: PRIVATE_INSTRUCTION, [var1]: filename, [var1]: contents })
        // Call AI KEY using the BUYER'S key (we never store it)
        const url = `${AI_URL}`;
        const ai = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", [process.env.AUTH_HEADER]: apiKey },
            body: JSON.stringify(body),
        });

        if (!ai.ok) {
            const txt = await ai.text().catch(() => "");
            console.log(`AI ${ai.status} ${ai.statusText}: ${txt}`)
            return res.status(502).json({ ok: false, error: `AI ${ai.status} ${ai.statusText}: ${txt}` });
        }
        const out = await ai.json().catch(() => null);
        const text = out?.candidates?.[0]?.content?.parts?.[0]?.text || "";
        if (!text) return res.status(502).json({ ok: false, error: "Empty AI response" });

        cacheSet(cacheKey, text);

        // Watermark (traceable but harmless)
        const wm = `\n--[[\n  Generated by: Script Header Generator v${pluginVersion || "1.0.0"}\n Author: TheCyberCairo \n Timestamp: ${new Date().toISOString()}\n]]\n`;
       
        return res.json({ ok: true, headerComment: stripCodeFences(text) + wm });
    } catch (e) {

        return res.status(500).json({ ok: false, error: String(e) });
    }
});
function stripCodeFences(s) {
    if (!s) return s;
    // remove opening fence with optional language
    s = s.replace(/^```[a-zA-Z]*\s*\n?/, "");
    // remove closing fence
    s = s.replace(/\n?```$/, "");
    return s.trim();
  }
function buildAICall(text) {
    const body = JSON.parse(process.env.AI_BODY_TEMPLATE);
    body[process.env.body1][0][process.env.body2] = text
    return body;
}

// ====== START ======
app.listen(PORT, () => {
    console.log(`[server] up on :${PORT} asset=${PLUGIN_ASSET_ID}`);
});
