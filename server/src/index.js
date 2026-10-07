import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { decodeClientDataJSON, isoBase64URL } from "@simplewebauthn/server/helpers";

const QR_TTL_MS = 10_000;      // 入口QRの切り替え間隔
const QR_GRACE_MS = 20_000;    // QR読み取り〜スマホでページが開くまでの猶予
const AUTH_TTL_MS = 120_000;   // ページを開いてからPasskey認証するまでの猶予
const REG_TTL_MS = 300_000;

export default {
  async fetch(request, env) {
    const cors = {
      "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    try {
      const { pathname } = new URL(request.url);
      const body = request.method === "POST" ? await request.json() : null;
      const route = routes[`${request.method} ${pathname}`];
      if (!route) throw new HttpError(404, "Not found");
      return json(await route(env, body), 200, cors);
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 400;
      return json({ error: e.message || String(e) }, status, cors);
    }
  },
};

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function json(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...headers, "Content-Type": "application/json; charset=utf-8" },
  });
}

function randomToken(bytes = 16) {
  return isoBase64URL.fromBuffer(crypto.getRandomValues(new Uint8Array(bytes)));
}

// 発行済みチャレンジを取り出して検証する（期限切れ・使用済み・種別違いは拒否）
async function takeChallenge(env, challenge, kind, graceMs = 0) {
  const row = await env.DB.prepare("SELECT * FROM challenges WHERE challenge = ? AND kind = ?")
    .bind(challenge, kind).first();
  if (!row) throw new Error("不明なチャレンジです。");
  if (row.used) throw new Error("このチャレンジは使用済みです。");
  if (Date.now() > row.expires_at + graceMs) throw new Error("有効期限が切れています。");
  return row;
}

const routes = {
  // ---- 端末登録 ----
  async "POST /api/register/options"(env, body) {
    const userId = String(body?.userId || "").trim();
    const displayName = String(body?.displayName || "").trim() || userId;
    if (!userId) throw new Error("ユーザーIDを入力してください。");

    const options = await generateRegistrationOptions({
      rpName: "勤怠デモ",
      rpID: env.RP_ID,
      userName: userId,
      userDisplayName: displayName,
      userID: new TextEncoder().encode(userId),
      attestationType: "none",
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "required",
        userVerification: "preferred",
      },
    });
    await env.DB.prepare(
      "INSERT INTO challenges (challenge, kind, user_id, display_name, expires_at) VALUES (?, 'reg', ?, ?, ?)"
    ).bind(options.challenge, userId, displayName, Date.now() + REG_TTL_MS).run();
    return options;
  },

  async "POST /api/register/verify"(env, body) {
    const response = body?.response;
    const { challenge } = decodeClientDataJSON(response.response.clientDataJSON);
    const reg = await takeChallenge(env, challenge, "reg");

    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: env.ALLOWED_ORIGIN,
      expectedRPID: env.RP_ID,
      requireUserVerification: false,
    });
    if (!verified) throw new Error("登録の検証に失敗しました。");

    const { credential } = registrationInfo;
    await env.DB.batch([
      env.DB.prepare("UPDATE challenges SET used = 1 WHERE challenge = ?").bind(challenge),
      env.DB.prepare(
        "INSERT OR REPLACE INTO credentials (id, user_id, display_name, public_key, counter, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(credential.id, reg.user_id, reg.display_name, isoBase64URL.fromBuffer(credential.publicKey),
        credential.counter, Date.now()),
    ]);
    return { userId: reg.user_id, displayName: reg.display_name, credentialId: credential.id };
  },

  // ---- 入口QR（PC/タブレット）----
  async "POST /api/qr"(env, body) {
    const office = String(body?.office || "OFFICE-A").slice(0, 32);
    const token = randomToken();
    const expiresAt = Date.now() + QR_TTL_MS;
    await env.DB.batch([
      // 古いチャレンジを掃除
      env.DB.prepare("DELETE FROM challenges WHERE expires_at < ?").bind(Date.now() - 3_600_000),
      env.DB.prepare("INSERT INTO challenges (challenge, kind, office, expires_at) VALUES (?, 'qr', ?, ?)")
        .bind(token, office, expiresAt),
    ]);
    return { token, office, expiresAt, serverTime: Date.now() };
  },

  // ---- 出社（スマホ）----
  // QRトークンを、このスマホ専用の1回限りの認証チャレンジに交換する
  async "POST /api/auth/options"(env, body) {
    const qr = await takeChallenge(env, String(body?.qr || ""), "qr", QR_GRACE_MS);
    const options = await generateAuthenticationOptions({
      rpID: env.RP_ID,
      userVerification: "preferred",
      allowCredentials: [],
    });
    await env.DB.prepare(
      "INSERT INTO challenges (challenge, kind, office, expires_at) VALUES (?, 'auth', ?, ?)"
    ).bind(options.challenge, qr.office, Date.now() + AUTH_TTL_MS).run();
    return { options, office: qr.office };
  },

  async "POST /api/auth/verify"(env, body) {
    const response = body?.response;
    const { challenge } = decodeClientDataJSON(response.response.clientDataJSON);
    const auth = await takeChallenge(env, challenge, "auth");

    const cred = await env.DB.prepare("SELECT * FROM credentials WHERE id = ?").bind(response.id).first();
    if (!cred) throw new Error("このPasskeyはサーバーに登録されていません。①で端末を登録し直してください。");

    const { verified, authenticationInfo } = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: env.ALLOWED_ORIGIN,
      expectedRPID: env.RP_ID,
      credential: {
        id: cred.id,
        publicKey: isoBase64URL.toBuffer(cred.public_key),
        counter: cred.counter,
      },
      requireUserVerification: false,
    });
    if (!verified) throw new Error("署名の検証に失敗しました。");

    const at = Date.now();
    await env.DB.batch([
      env.DB.prepare("UPDATE challenges SET used = 1 WHERE challenge = ?").bind(challenge),
      env.DB.prepare("UPDATE credentials SET counter = ? WHERE id = ?").bind(authenticationInfo.newCounter, cred.id),
      env.DB.prepare("INSERT INTO attendance (user_id, office, at, credential_id) VALUES (?, ?, ?, ?)")
        .bind(cred.user_id, auth.office, at, cred.id),
    ]);
    return { userId: cred.user_id, displayName: cred.display_name, office: auth.office, at };
  },

  // ---- 勤怠ログ（PC画面で表示）----
  async "GET /api/attendance"(env) {
    const { results } = await env.DB.prepare(
      `SELECT a.id, a.user_id AS userId, c.display_name AS displayName, a.office, a.at
       FROM attendance a LEFT JOIN credentials c ON c.id = a.credential_id
       ORDER BY a.id DESC LIMIT 30`
    ).all();
    return { logs: results, serverTime: Date.now() };
  },
};
