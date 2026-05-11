import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";
import QRCode from "qrcode";
import { Resend } from "resend";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const LOG_HASH_SECRET = process.env.LOG_HASH_SECRET || "lukintosh-dev-secret";

const PUBLIC_SITE_URL =
  process.env.PUBLIC_SITE_URL || "https://myaccount.lukintosh.com";

const API_BASE_URL =
  process.env.API_BASE_URL || "https://auth.lukintosh.com";

const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || null;
const isProduction = process.env.NODE_ENV === "production";

const RESEND_API_KEY = process.env.RESEND_API_KEY || null;
const EMAIL_FROM =
  process.env.EMAIL_FROM || "Lukintosh Accounts <onboarding@resend.dev>";
const EMAIL_REPLY_TO =
  process.env.EMAIL_REPLY_TO || "security@lukintosh.com";

const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_ANON_KEY");
  process.exit(1);
}

if (!SUPABASE_SERVICE_ROLE_KEY) {
  console.warn("SUPABASE_SERVICE_ROLE_KEY is missing. Database writes may fail.");
}

const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5173",
  "https://lukintosh.com",
  "https://www.lukintosh.com",
  "https://myaccount.lukintosh.com",
  "https://auth.lukintosh.com",
  PUBLIC_SITE_URL,
  API_BASE_URL
];

const ALLOWED_RETURN_ORIGINS = new Set([
  "https://lukintosh.com",
  "https://www.lukintosh.com",
  "https://myaccount.lukintosh.com",
  "https://auth.lukintosh.com"
]);

const pkceStore = new Map();

const serverPkceStorage = {
  getItem: (key) => pkceStore.get(key) || null,
  setItem: (key, value) => pkceStore.set(key, value),
  removeItem: (key) => pkceStore.delete(key)
};

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    flowType: "pkce",
    detectSessionInUrl: false,
    persistSession: false,
    autoRefreshToken: false,
    storage: serverPkceStorage
  }
});

const db = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY || SUPABASE_ANON_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: "500kb" }));
app.use(cookieParser());

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true
  })
);

function getFrontendUrl(path = "") {
  const base = PUBLIC_SITE_URL.replace(/\/$/, "");
  const cleanPath = String(path || "");

  if (!cleanPath) return base;

  if (cleanPath.startsWith("?")) {
    return `${base}/${cleanPath}`;
  }

  if (cleanPath.startsWith("/")) {
    return `${base}${cleanPath}`;
  }

  return `${base}/${cleanPath}`;
}

function getApiUrl(path = "") {
  const base = API_BASE_URL.replace(/\/$/, "");
  const cleanPath = String(path || "");

  if (!cleanPath) return base;

  if (cleanPath.startsWith("/")) {
    return `${base}${cleanPath}`;
  }

  return `${base}/${cleanPath}`;
}

function normalizeReturnTo(value) {
  try {
    if (!value) return PUBLIC_SITE_URL;

    const url = new URL(String(value));

    if (!ALLOWED_RETURN_ORIGINS.has(url.origin)) {
      return PUBLIC_SITE_URL;
    }

    return url.toString();
  } catch {
    return PUBLIC_SITE_URL;
  }
}

function getCookieOptions(extra = {}) {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    path: "/",
    ...(isProduction && COOKIE_DOMAIN ? { domain: COOKIE_DOMAIN } : {}),
    ...extra
  };
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function hashValue(value) {
  if (!value) return null;

  return crypto
    .createHash("sha256")
    .update(`${LOG_HASH_SECRET}:${value}`)
    .digest("hex");
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];

  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }

  return req.socket.remoteAddress || null;
}

function getUserAgent(req) {
  return String(req.headers["user-agent"] || "Unknown").slice(0, 500);
}

function parseDevice(userAgent) {
  const ua = userAgent.toLowerCase();

  let browser = "Unknown browser";
  let os = "Unknown OS";

  if (ua.includes("edg/")) browser = "Microsoft Edge";
  else if (ua.includes("chrome/")) browser = "Google Chrome";
  else if (ua.includes("safari/")) browser = "Safari";
  else if (ua.includes("firefox/")) browser = "Firefox";

  if (ua.includes("windows")) os = "Windows";
  else if (ua.includes("iphone")) os = "iPhone";
  else if (ua.includes("ipad")) os = "iPad";
  else if (ua.includes("android")) os = "Android";
  else if (ua.includes("mac os")) os = "macOS";
  else if (ua.includes("linux")) os = "Linux";

  return {
    browser,
    os,
    deviceName: `${os} · ${browser}`
  };
}

function setAuthCookies(res, session, internalSessionId) {
  const cookieOptions = getCookieOptions();

  res.cookie("lk_access_token", session.access_token, {
    ...cookieOptions,
    maxAge: 1000 * 60 * 60
  });

  res.cookie("lk_refresh_token", session.refresh_token, {
    ...cookieOptions,
    maxAge: 1000 * 60 * 60 * 24 * 30
  });

  res.cookie("lk_session_id", internalSessionId, {
    ...cookieOptions,
    maxAge: 1000 * 60 * 60 * 24 * 30
  });
}

function clearAuthCookies(res) {
  const options = getCookieOptions();

  res.clearCookie("lk_access_token", options);
  res.clearCookie("lk_refresh_token", options);
  res.clearCookie("lk_session_id", options);
  res.clearCookie("lk_oauth_return_to", options);

  res.cookie("lk_access_token", "", {
    ...options,
    maxAge: 0,
    expires: new Date(0)
  });

  res.cookie("lk_refresh_token", "", {
    ...options,
    maxAge: 0,
    expires: new Date(0)
  });

  res.cookie("lk_session_id", "", {
    ...options,
    maxAge: 0,
    expires: new Date(0)
  });

  res.cookie("lk_oauth_return_to", "", {
    ...options,
    maxAge: 0,
    expires: new Date(0)
  });
}

function setOAuthReturnCookie(res, returnTo) {
  res.cookie(
    "lk_oauth_return_to",
    normalizeReturnTo(returnTo),
    getCookieOptions({
      maxAge: 1000 * 60 * 10
    })
  );
}

function getOAuthReturnTo(req) {
  return normalizeReturnTo(
    req.query.returnTo ||
      req.cookies.lk_oauth_return_to ||
      PUBLIC_SITE_URL
  );
}

function clearOAuthReturnCookie(res) {
  const options = getCookieOptions();

  res.clearCookie("lk_oauth_return_to", options);

  res.cookie("lk_oauth_return_to", "", {
    ...options,
    maxAge: 0,
    expires: new Date(0)
  });
}

function createAuthedSupabaseClient(accessToken) {
  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    },
    global: {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    }
  });
}

function formatProviderName(provider) {
  const map = {
    email: "Email",
    google: "Google",
    github: "GitHub",
    azure: "Microsoft",
    apple: "Apple"
  };

  return map[provider] || provider || "Unknown";
}

function getLastUsedProvider(user) {
  const providers = user.app_metadata?.providers || [];
  const mainProvider = user.app_metadata?.provider || providers[0] || "email";

  const identities = Array.isArray(user.identities) ? user.identities : [];

  const sortedIdentities = identities
    .filter((identity) => identity?.provider)
    .sort((a, b) => {
      const aTime = new Date(
        a.last_sign_in_at || a.updated_at || a.created_at || 0
      ).getTime();

      const bTime = new Date(
        b.last_sign_in_at || b.updated_at || b.created_at || 0
      ).getTime();

      return bTime - aTime;
    });

  return sortedIdentities[0]?.provider || mainProvider;
}

function publicUser(user) {
  const providers = user.app_metadata?.providers || [];
  const mainProvider = user.app_metadata?.provider || providers[0] || "email";
  const lastUsedProvider = getLastUsedProvider(user);

  return {
    id: user.id,
    email: user.email,
    displayName:
      user.user_metadata?.display_name ||
      user.user_metadata?.name ||
      user.user_metadata?.full_name ||
      user.email?.split("@")[0] ||
      "Lukintosh Account",

    avatarUrl:
      user.user_metadata?.avatar_url ||
      user.user_metadata?.picture ||
      null,

    provider: mainProvider,
    providerName: formatProviderName(mainProvider),

    lastUsedProvider,
    lastUsedProviderName: formatProviderName(lastUsedProvider),

    providers,
    providerNames: providers.map(formatProviderName),

    identities: Array.isArray(user.identities)
      ? user.identities.map((identity) => ({
          id: identity.id,
          provider: identity.provider,
          providerName: formatProviderName(identity.provider),
          identityData: identity.identity_data || {},
          createdAt: identity.created_at,
          updatedAt: identity.updated_at,
          lastSignInAt: identity.last_sign_in_at
        }))
      : [],

    createdAt: user.created_at,
    lastSignInAt: user.last_sign_in_at,
    emailConfirmedAt: user.email_confirmed_at
  };
}

/* =========================
   EMAILS / RESEND
========================= */

function getSecurityEmailBase({ title, preview, body }) {
  return `
    <!doctype html>
    <html lang="pt-BR">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
      </head>
      <body style="margin:0;background:#050507;color:#f5f5f7;font-family:Inter,Arial,sans-serif;">
        <div style="display:none;max-height:0;overflow:hidden;opacity:0;">
          ${escapeHtml(preview)}
        </div>

        <div style="max-width:640px;margin:0 auto;padding:32px 18px;">
          <div style="border:1px solid rgba(255,255,255,.14);background:#0b0b10;border-radius:28px;overflow:hidden;">
            <div style="padding:28px 28px 18px;">
              <div style="display:inline-block;width:42px;height:42px;border-radius:14px;background:linear-gradient(145deg,#fff,#8ab4ff 45%,#b49cff);margin-bottom:18px;"></div>

              <h1 style="margin:0;font-size:30px;line-height:1;letter-spacing:-1.4px;color:#f5f5f7;">
                ${escapeHtml(title)}
              </h1>

              <p style="margin:12px 0 0;color:#a6a6ad;line-height:1.55;font-size:15px;">
                Lukintosh Accounts Security
              </p>
            </div>

            <div style="padding:0 28px 28px;">
              ${body}

              <div style="margin-top:26px;padding-top:18px;border-top:1px solid rgba(255,255,255,.12);">
                <p style="margin:0;color:#73737d;font-size:12px;line-height:1.55;">
                  Este e-mail foi enviado automaticamente por Lukintosh Accounts.
                  Se você não reconhece essa atividade, altere sua senha e revise suas sessões.
                </p>
              </div>
            </div>
          </div>
        </div>
      </body>
    </html>
  `;
}

async function sendEmail({ to, subject, html }) {
  if (!resend) {
    console.warn("Resend disabled: RESEND_API_KEY is missing.");
    return { skipped: true };
  }

  const { data, error } = await resend.emails.send({
    from: EMAIL_FROM,
    to: [to],
    subject,
    html,
    replyTo: EMAIL_REPLY_TO
  });

  if (error) {
    console.warn("Resend email failed:", error);
    return { error };
  }

  return { data };
}

async function sendNewLoginEmail({
  user,
  req,
  providerLabel = "Lukintosh Accounts"
}) {
  if (!user?.email) return { skipped: true };

  const userAgent = getUserAgent(req);
  const parsed = parseDevice(userAgent);
  const ip = getClientIp(req);

  const when = new Date().toLocaleString("pt-BR", {
    timeZone: "America/Sao_Paulo"
  });

  const html = getSecurityEmailBase({
    title: "Novo login detectado",
    preview: "Um novo login foi detectado na sua conta Lukintosh.",
    body: `
      <p style="margin:0 0 18px;color:#d9d9df;line-height:1.6;font-size:15px;">
        Detectamos um novo acesso à sua conta Lukintosh.
      </p>

      <div style="border:1px solid rgba(255,255,255,.12);border-radius:20px;padding:16px;background:rgba(255,255,255,.05);">
        <p style="margin:0 0 8px;color:#a6a6ad;font-size:13px;">Conta</p>
        <p style="margin:0 0 14px;color:#f5f5f7;font-size:15px;">${escapeHtml(user.email)}</p>

        <p style="margin:0 0 8px;color:#a6a6ad;font-size:13px;">Método</p>
        <p style="margin:0 0 14px;color:#f5f5f7;font-size:15px;">${escapeHtml(providerLabel)}</p>

        <p style="margin:0 0 8px;color:#a6a6ad;font-size:13px;">Dispositivo</p>
        <p style="margin:0 0 14px;color:#f5f5f7;font-size:15px;">${escapeHtml(parsed.deviceName)}</p>

        <p style="margin:0 0 8px;color:#a6a6ad;font-size:13px;">IP aproximado</p>
        <p style="margin:0 0 14px;color:#f5f5f7;font-size:15px;">${escapeHtml(ip || "Indisponível")}</p>

        <p style="margin:0 0 8px;color:#a6a6ad;font-size:13px;">Data</p>
        <p style="margin:0;color:#f5f5f7;font-size:15px;">${escapeHtml(when)}</p>
      </div>

      <a href="${escapeHtml(PUBLIC_SITE_URL)}"
         style="display:inline-block;margin-top:20px;background:#f5f5f7;color:#050507;text-decoration:none;font-weight:800;border-radius:999px;padding:13px 18px;">
        Revisar minha conta
      </a>
    `
  });

  return sendEmail({
    to: user.email,
    subject: "Novo login detectado na sua conta Lukintosh",
    html
  });
}

/* =========================
   LOGS / SESSIONS
========================= */

async function logEvent(req, options = {}) {
  try {
    const userId = options.userId || req.user?.id || null;
    const ip = getClientIp(req);
    const userAgent = getUserAgent(req);

    await db.from("audit_logs").insert({
      user_id: userId,
      action: options.action,
      target: options.target || null,
      ip_hash: hashValue(ip),
      user_agent: userAgent,
      metadata: options.metadata || {}
    });
  } catch (error) {
    console.warn("Audit log failed:", error.message);
  }
}

async function registerDeviceAndSession(req, res, user, session) {
  try {
    const ip = getClientIp(req);
    const userAgent = getUserAgent(req);
    const parsed = parseDevice(userAgent);
    const deviceFingerprint = hashValue(`${user.id}:${userAgent}`);

    let deviceId = null;

    const { data: existingDevice } = await db
      .from("devices")
      .select("*")
      .eq("user_id", user.id)
      .eq("device_fingerprint", deviceFingerprint)
      .maybeSingle();

    if (existingDevice) {
      deviceId = existingDevice.id;

      await db
        .from("devices")
        .update({
          browser: parsed.browser,
          os: parsed.os,
          device_name: parsed.deviceName,
          ip_hash: hashValue(ip),
          user_agent: userAgent,
          last_seen_at: new Date().toISOString()
        })
        .eq("id", deviceId)
        .eq("user_id", user.id);
    } else {
      const { data: newDevice, error: deviceError } = await db
        .from("devices")
        .insert({
          user_id: user.id,
          device_name: parsed.deviceName,
          browser: parsed.browser,
          os: parsed.os,
          device_fingerprint: deviceFingerprint,
          ip_hash: hashValue(ip),
          user_agent: userAgent,
          trusted: false
        })
        .select()
        .single();

      if (deviceError) {
        console.warn("Create device failed:", deviceError.message);
      }

      deviceId = newDevice?.id || null;
    }

    const internalSessionId = crypto.randomUUID();

    const { error: sessionError } = await db.from("account_sessions").insert({
      id: internalSessionId,
      user_id: user.id,
      device_id: deviceId,
      refresh_token_hash: hashValue(session.refresh_token),
      browser: parsed.browser,
      os: parsed.os,
      ip_hash: hashValue(ip),
      location_label: "Approximate location hidden",
      revoked: false,
      current: true,
      last_seen_at: new Date().toISOString()
    });

    if (sessionError) {
      console.warn("Create internal session failed:", sessionError.message);
    }

    setAuthCookies(res, session, internalSessionId);

    return {
      deviceId,
      internalSessionId
    };
  } catch (error) {
    console.warn("Device/session registration failed:", error.message);

    const fallbackSessionId = crypto.randomUUID();
    setAuthCookies(res, session, fallbackSessionId);

    return {
      deviceId: null,
      internalSessionId: fallbackSessionId
    };
  }
}

async function getMfaState(accessToken) {
  const authedSupabase = createAuthedSupabaseClient(accessToken);

  const { data: factorsData, error: factorsError } =
    await authedSupabase.auth.mfa.listFactors();

  if (factorsError) throw factorsError;

  const { data: aalData, error: aalError } =
    await authedSupabase.auth.mfa.getAuthenticatorAssuranceLevel();

  if (aalError) throw aalError;

  const totpFactors = factorsData?.totp || [];
  const verifiedTotpFactors = totpFactors.filter(
    (factor) => factor.status === "verified"
  );

  return {
    enabled: verifiedTotpFactors.length > 0,
    currentLevel: aalData?.currentLevel || "aal1",
    nextLevel: aalData?.nextLevel || null,
    needsChallenge:
      verifiedTotpFactors.length > 0 &&
      aalData?.currentLevel !== "aal2" &&
      aalData?.nextLevel === "aal2",
    factors: verifiedTotpFactors.map((factor) => ({
      id: factor.id,
      friendlyName: factor.friendly_name,
      factorType: factor.factor_type,
      status: factor.status,
      createdAt: factor.created_at,
      updatedAt: factor.updated_at
    }))
  };
}

async function refreshSessionIfNeeded(req, res) {
  const accessToken = req.cookies.lk_access_token;
  const refreshToken = req.cookies.lk_refresh_token;
  const internalSessionId = req.cookies.lk_session_id;

  if (internalSessionId) {
    const { data: internalSession } = await db
      .from("account_sessions")
      .select("revoked")
      .eq("id", internalSessionId)
      .maybeSingle();

    if (internalSession?.revoked) {
      clearAuthCookies(res);
      return null;
    }
  }

  if (accessToken) {
    const { data, error } = await supabase.auth.getUser(accessToken);

    if (!error && data.user) {
      if (internalSessionId) {
        await db
          .from("account_sessions")
          .update({
            last_seen_at: new Date().toISOString()
          })
          .eq("id", internalSessionId)
          .eq("user_id", data.user.id);
      }

      return {
        user: data.user,
        accessToken
      };
    }
  }

  if (!refreshToken) return null;

  const { data, error } = await supabase.auth.refreshSession({
    refresh_token: refreshToken
  });

  if (error || !data.session || !data.user) {
    clearAuthCookies(res);
    return null;
  }

  setAuthCookies(res, data.session, internalSessionId || crypto.randomUUID());

  return {
    user: data.user,
    accessToken: data.session.access_token
  };
}

async function requireAuth(req, res, next) {
  try {
    const auth = await refreshSessionIfNeeded(req, res);

    if (!auth) {
      return res.status(401).json({
        ok: false,
        error: "not_authenticated"
      });
    }

    req.user = auth.user;
    req.accessToken = auth.accessToken;

    return next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    clearAuthCookies(res);

    return res.status(401).json({
      ok: false,
      error: "invalid_session"
    });
  }
}

async function requireMfaIfEnabled(req, res, next) {
  try {
    const mfa = await getMfaState(req.accessToken);

    if (mfa.needsChallenge) {
      return res.status(403).json({
        ok: false,
        error: "mfa_required",
        mfa
      });
    }

    req.mfa = mfa;

    return next();
  } catch (error) {
    console.error("MFA guard error:", error);

    return res.status(403).json({
      ok: false,
      error: "mfa_check_failed"
    });
  }
}

/* =========================
   HEALTH
========================= */

app.get("/", (req, res) => {
  return res.json({
    ok: true,
    service: "Lukintosh Accounts Auth Service",
    frontend: PUBLIC_SITE_URL,
    api: API_BASE_URL,
    cookieDomain: COOKIE_DOMAIN,
    emailEnabled: Boolean(resend)
  });
});

app.get("/api/health", (req, res) => {
  return res.json({
    ok: true,
    service: "Lukintosh Accounts API",
    status: "operational",
    frontend: PUBLIC_SITE_URL,
    api: API_BASE_URL,
    cookieDomain: COOKIE_DOMAIN,
    emailEnabled: Boolean(resend)
  });
});

/* =========================
   OAUTH CALLBACK
========================= */

app.get("/auth/callback", async (req, res) => {
  try {
    const code = req.query.code;
    const error = req.query.error;
    const errorDescription = req.query.error_description;

    if (error) {
      console.error("OAuth provider returned error:", error, errorDescription);

      return res.redirect(
        getFrontendUrl(
          `?error=${encodeURIComponent(String(errorDescription || error))}`
        )
      );
    }

    if (!code) {
      return res.redirect(
        getFrontendUrl("?error=missing_oauth_code_pkce_required")
      );
    }

    const { data, error: exchangeError } =
      await supabase.auth.exchangeCodeForSession(String(code));

    if (exchangeError || !data.session || !data.user) {
      console.error("OAuth callback error:", exchangeError);

      return res.redirect(
        getFrontendUrl(
          `?error=${encodeURIComponent(exchangeError?.message || "oauth_failed")}`
        )
      );
    }

    await registerDeviceAndSession(req, res, data.user, data.session);

    req.user = data.user;
    req.accessToken = data.session.access_token;

    const provider = data.user.app_metadata?.provider || "oauth";

    sendNewLoginEmail({
      user: data.user,
      req,
      providerLabel: formatProviderName(provider)
    }).catch((emailError) => {
      console.warn("OAuth login email failed:", emailError.message);
    });

    await logEvent(req, {
      userId: data.user.id,
      action: "account.oauth_login",
      target: "auth.user",
      metadata: {
        provider: data.user.app_metadata?.provider || "unknown",
        providers: data.user.app_metadata?.providers || []
      }
    });

    const returnTo = getOAuthReturnTo(req);
    clearOAuthReturnCookie(res);

    return res.redirect(returnTo);
  } catch (error) {
    console.error("OAuth callback fatal error:", error);

    return res.redirect(getFrontendUrl("?error=oauth_callback_failed"));
  }
});

/* =========================
   OAUTH PROVIDERS
========================= */

app.get("/auth/:provider", async (req, res) => {
  try {
    const providerAliases = {
      google: "google",
      github: "github",
      microsoft: "azure",
      azure: "azure",
      apple: "apple"
    };

    const requestedProvider = String(req.params.provider || "").toLowerCase();

    if (requestedProvider === "callback") {
      return res.redirect(getFrontendUrl("?error=invalid_oauth_callback_route"));
    }

    const provider = providerAliases[requestedProvider];

    if (!provider) {
      return res.status(400).send(`Provider not allowed: ${requestedProvider}`);
    }

    const returnTo = normalizeReturnTo(req.query.returnTo || PUBLIC_SITE_URL);
    setOAuthReturnCookie(res, returnTo);

    const callbackBaseUrl = API_BASE_URL.replace(/\/$/, "");

    const scopes =
      provider === "azure"
        ? "openid profile email https://graph.microsoft.com/User.Read"
        : provider === "github"
          ? "read:user user:email"
          : "email profile";

    const { data, error } = await supabase.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: `${callbackBaseUrl}/auth/callback?returnTo=${encodeURIComponent(returnTo)}`,
        scopes,
        queryParams: {
          prompt: "select_account"
        }
      }
    });

    if (error || !data.url) {
      console.error("OAuth URL error:", error);

      return res.status(400).send(error?.message || "OAuth URL error");
    }

    return res.redirect(data.url);
  } catch (error) {
    console.error("OAuth start error:", error);

    return res.status(500).send("OAuth start failed");
  }
});

/* =========================
   EMAIL/PASSWORD AUTH
========================= */

app.post("/api/signup", async (req, res) => {
  try {
    const { email, password, displayName } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        ok: false,
        error: "email_and_password_required"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        ok: false,
        error: "A senha precisa ter pelo menos 8 caracteres."
      });
    }

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          display_name: displayName || "Lukintosh Account"
        },
        emailRedirectTo: getApiUrl("/auth/callback")
      }
    });

    if (error) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    if (data.session && data.user) {
      await registerDeviceAndSession(req, res, data.user, data.session);

      req.user = data.user;
      req.accessToken = data.session.access_token;

      sendNewLoginEmail({
        user: data.user,
        req,
        providerLabel: "E-mail e senha"
      }).catch((emailError) => {
        console.warn("Signup login email failed:", emailError.message);
      });

      await logEvent(req, {
        userId: data.user.id,
        action: "account.signup",
        target: "auth.user"
      });
    }

    return res.json({
      ok: true,
      message: data.session
        ? "Conta criada e login realizado."
        : "Conta criada. Verifique seu e-mail se a confirmação estiver ativada.",
      user: data.user ? publicUser(data.user) : null
    });
  } catch (error) {
    console.error("Signup error:", error);

    return res.status(500).json({
      ok: false,
      error: "internal_server_error"
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        ok: false,
        error: "email_and_password_required"
      });
    }

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error || !data.session || !data.user) {
      await logEvent(req, {
        action: "account.login_failed",
        target: "auth.user",
        metadata: { email }
      });

      return res.status(401).json({
        ok: false,
        error: error?.message || "invalid_login"
      });
    }

    await registerDeviceAndSession(req, res, data.user, data.session);

    req.user = data.user;
    req.accessToken = data.session.access_token;

    const mfa = await getMfaState(data.session.access_token).catch(() => null);

    sendNewLoginEmail({
      user: data.user,
      req,
      providerLabel: "E-mail e senha"
    }).catch((emailError) => {
      console.warn("Password login email failed:", emailError.message);
    });

    await logEvent(req, {
      userId: data.user.id,
      action: "account.login",
      target: "auth.user",
      metadata: {
        mfaRequired: Boolean(mfa?.needsChallenge)
      }
    });

    return res.json({
      ok: true,
      user: publicUser(data.user),
      mfaRequired: Boolean(mfa?.needsChallenge),
      mfa
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      ok: false,
      error: "internal_server_error"
    });
  }
});

app.post("/api/logout", async (req, res) => {
  try {
    const accessToken = req.cookies.lk_access_token;
    const internalSessionId = req.cookies.lk_session_id;

    let userId = null;

    if (accessToken) {
      const { data } = await supabase.auth.getUser(accessToken);
      userId = data?.user?.id || null;

      const authedSupabase = createAuthedSupabaseClient(accessToken);

      await authedSupabase.auth.signOut({
        scope: "local"
      }).catch((error) => {
        console.warn("Supabase signOut failed:", error.message);
      });
    }

    if (internalSessionId && userId) {
      await db
        .from("account_sessions")
        .update({
          revoked: true,
          current: false,
          last_seen_at: new Date().toISOString()
        })
        .eq("id", internalSessionId)
        .eq("user_id", userId);
    }

    await logEvent(req, {
      userId,
      action: "account.logout",
      target: "auth.session"
    });

    clearAuthCookies(res);

    return res.json({
      ok: true
    });
  } catch (error) {
    console.error("Logout error:", error);

    clearAuthCookies(res);

    return res.json({
      ok: true
    });
  }
});

/* =========================
   MFA / 2FA REAL
========================= */

app.get("/api/mfa/status", requireAuth, async (req, res) => {
  try {
    const mfa = await getMfaState(req.accessToken);

    return res.json({
      ok: true,
      mfa
    });
  } catch (error) {
    console.error("MFA status error:", error);

    return res.status(400).json({
      ok: false,
      error: error.message || "mfa_status_failed"
    });
  }
});

app.post("/api/mfa/enroll", requireAuth, async (req, res) => {
  try {
    const { friendlyName } = req.body;

    const authedSupabase = createAuthedSupabaseClient(req.accessToken);

    const uniqueFriendlyName = `${friendlyName || "Lukintosh Accounts"} ${Date.now()}`;

    const { data, error } = await authedSupabase.auth.mfa.enroll({
      factorType: "totp",
      friendlyName: uniqueFriendlyName
    });

    if (error) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    const secret = data.totp?.secret || null;
    const supabaseQrCode = data.totp?.qr_code || null;

    let uri = null;

    if (secret) {
      const issuerName = "Lukintosh Accounts";
      const accountName = req.user.email || "account";

      const issuer = encodeURIComponent(issuerName);
      const label = encodeURIComponent(`${issuerName}:${accountName}`);

      uri = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    }

    let qrImage = null;

    if (uri) {
      qrImage = await QRCode.toDataURL(uri, {
        type: "image/png",
        width: 260,
        margin: 2,
        errorCorrectionLevel: "M"
      });
    }

    await logEvent(req, {
      action: "mfa.enroll_started",
      target: "auth.factor",
      metadata: {
        factorId: data.id,
        factorType: "totp",
        friendlyName: uniqueFriendlyName
      }
    });

    return res.json({
      ok: true,
      factorId: data.id,
      factorType: data.type || "totp",
      friendlyName: uniqueFriendlyName,
      qrImage,
      qrCode: supabaseQrCode,
      secret,
      uri
    });
  } catch (error) {
    console.error("MFA enroll error:", error);

    return res.status(500).json({
      ok: false,
      error: error.message || "internal_server_error"
    });
  }
});

app.post("/api/mfa/verify", requireAuth, async (req, res) => {
  try {
    const { factorId, code } = req.body;

    if (!factorId || !code) {
      return res.status(400).json({
        ok: false,
        error: "factor_id_and_code_required"
      });
    }

    const authedSupabase = createAuthedSupabaseClient(req.accessToken);

    const { data: challengeData, error: challengeError } =
      await authedSupabase.auth.mfa.challenge({ factorId });

    if (challengeError) {
      return res.status(400).json({
        ok: false,
        error: challengeError.message
      });
    }

    const { data, error } = await authedSupabase.auth.mfa.verify({
      factorId,
      challengeId: challengeData.id,
      code
    });

    if (error) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    if (data?.access_token && data?.refresh_token) {
      setAuthCookies(
        res,
        {
          access_token: data.access_token,
          refresh_token: data.refresh_token
        },
        req.cookies.lk_session_id || crypto.randomUUID()
      );
    }

    await logEvent(req, {
      action: "mfa.enabled",
      target: "auth.factor",
      metadata: { factorId }
    });

    return res.json({
      ok: true,
      message: "2FA ativado com sucesso."
    });
  } catch (error) {
    console.error("MFA verify error:", error);

    return res.status(500).json({
      ok: false,
      error: "internal_server_error"
    });
  }
});

app.post("/api/mfa/challenge", requireAuth, async (req, res) => {
  try {
    const { factorId } = req.body;

    if (!factorId) {
      return res.status(400).json({
        ok: false,
        error: "factor_id_required"
      });
    }

    const authedSupabase = createAuthedSupabaseClient(req.accessToken);

    const { data, error } = await authedSupabase.auth.mfa.challenge({
      factorId
    });

    if (error) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    return res.json({
      ok: true,
      challengeId: data.id
    });
  } catch (error) {
    console.error("MFA challenge error:", error);

    return res.status(500).json({
      ok: false,
      error: "internal_server_error"
    });
  }
});

app.post("/api/mfa/challenge-verify", requireAuth, async (req, res) => {
  try {
    const { factorId, challengeId, code } = req.body;

    if (!factorId || !challengeId || !code) {
      return res.status(400).json({
        ok: false,
        error: "factor_id_challenge_id_and_code_required"
      });
    }

    const authedSupabase = createAuthedSupabaseClient(req.accessToken);

    const { data, error } = await authedSupabase.auth.mfa.verify({
      factorId,
      challengeId,
      code
    });

    if (error) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    if (data?.access_token && data?.refresh_token) {
      setAuthCookies(
        res,
        {
          access_token: data.access_token,
          refresh_token: data.refresh_token
        },
        req.cookies.lk_session_id || crypto.randomUUID()
      );
    }

    await logEvent(req, {
      action: "mfa.challenge_verified",
      target: "auth.factor",
      metadata: { factorId }
    });

    return res.json({
      ok: true,
      message: "2FA verificado."
    });
  } catch (error) {
    console.error("MFA challenge verify error:", error);

    return res.status(500).json({
      ok: false,
      error: "internal_server_error"
    });
  }
});

app.delete("/api/mfa/factors/:factorId", requireAuth, requireMfaIfEnabled, async (req, res) => {
  try {
    const { factorId } = req.params;

    const authedSupabase = createAuthedSupabaseClient(req.accessToken);

    const { error } = await authedSupabase.auth.mfa.unenroll({
      factorId
    });

    if (error) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    await logEvent(req, {
      action: "mfa.disabled",
      target: "auth.factor",
      metadata: { factorId }
    });

    return res.json({
      ok: true,
      message: "2FA desativado."
    });
  } catch (error) {
    console.error("MFA unenroll error:", error);

    return res.status(500).json({
      ok: false,
      error: "internal_server_error"
    });
  }
});

/* =========================
   ACCOUNT
========================= */

app.get("/api/me", requireAuth, async (req, res) => {
  const mfa = await getMfaState(req.accessToken).catch(() => null);

  return res.json({
    ok: true,
    user: publicUser(req.user),
    mfa
  });
});

app.patch("/api/me", requireAuth, requireMfaIfEnabled, async (req, res) => {
  try {
    const { displayName } = req.body;

    if (!displayName || displayName.trim().length < 2) {
      return res.status(400).json({
        ok: false,
        error: "O nome precisa ter pelo menos 2 caracteres."
      });
    }

    const authedSupabase = createAuthedSupabaseClient(req.accessToken);

    const { data, error } = await authedSupabase.auth.updateUser({
      data: {
        display_name: displayName.trim()
      }
    });

    if (error) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    await logEvent(req, {
      action: "profile.updated",
      target: "auth.user",
      metadata: {
        displayName: displayName.trim()
      }
    });

    return res.json({
      ok: true,
      user: publicUser(data.user)
    });
  } catch (error) {
    console.error("Update profile error:", error);

    return res.status(500).json({
      ok: false,
      error: "internal_server_error"
    });
  }
});

app.patch("/api/password", requireAuth, requireMfaIfEnabled, async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({
        ok: false,
        error: "A nova senha precisa ter pelo menos 8 caracteres."
      });
    }

    const authedSupabase = createAuthedSupabaseClient(req.accessToken);

    const { error } = await authedSupabase.auth.updateUser({
      password: newPassword
    });

    if (error) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    await logEvent(req, {
      action: "password.changed",
      target: "auth.user"
    });

    return res.json({
      ok: true,
      message: "Senha atualizada com sucesso."
    });
  } catch (error) {
    console.error("Password update error:", error);

    return res.status(500).json({
      ok: false,
      error: "internal_server_error"
    });
  }
});

app.get("/api/account-status", requireAuth, async (req, res) => {
  const { count: sessionCount } = await db
    .from("account_sessions")
    .select("*", { count: "exact", head: true })
    .eq("user_id", req.user.id)
    .eq("revoked", false);

  const { count: deviceCount } = await db
    .from("devices")
    .select("*", { count: "exact", head: true })
    .eq("user_id", req.user.id);

  const mfa = await getMfaState(req.accessToken).catch(() => ({
    enabled: false,
    currentLevel: "aal1",
    nextLevel: null,
    needsChallenge: false,
    factors: []
  }));

  const securityChecks = {
    emailVerified: Boolean(req.user.email_confirmed_at),
    mfaEnabled: Boolean(mfa.enabled),
    sessionActive: true,
    hasDeviceRecord: Number(deviceCount || 0) > 0
  };

  const passedChecks = Object.values(securityChecks).filter(Boolean).length;
  const totalChecks = Object.values(securityChecks).length;

  return res.json({
    ok: true,
    account: {
      verified: Boolean(req.user.email_confirmed_at),
      provider: req.user.app_metadata?.provider || "email",
      providers: req.user.app_metadata?.providers || [],
      mfa,
      twoFactorEnabled: mfa.enabled,
      activeSessions: sessionCount || 0,
      devices: deviceCount || 0,
      securityChecks,
      securityScore: Math.round((passedChecks / totalChecks) * 100)
    }
  });
});

/* =========================
   DEVICES
========================= */

app.get("/api/devices", requireAuth, requireMfaIfEnabled, async (req, res) => {
  const { data, error } = await db
    .from("devices")
    .select("id, device_name, browser, os, trusted, last_seen_at, created_at")
    .eq("user_id", req.user.id)
    .order("last_seen_at", { ascending: false });

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  return res.json({
    ok: true,
    devices: data || []
  });
});

app.patch("/api/devices/:id/trust", requireAuth, requireMfaIfEnabled, async (req, res) => {
  const { trusted } = req.body;

  const { data, error } = await db
    .from("devices")
    .update({ trusted: Boolean(trusted) })
    .eq("id", req.params.id)
    .eq("user_id", req.user.id)
    .select("id, trusted")
    .single();

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  await logEvent(req, {
    action: Boolean(trusted) ? "device.trusted" : "device.untrusted",
    target: "device",
    metadata: {
      deviceId: req.params.id
    }
  });

  return res.json({
    ok: true,
    device: data
  });
});

/* =========================
   SESSIONS
========================= */

app.get("/api/sessions", requireAuth, async (req, res) => {
  const currentSessionId = req.cookies.lk_session_id;

  const { data, error } = await db
    .from("account_sessions")
    .select("id, device_id, browser, os, location_label, revoked, last_seen_at, created_at")
    .eq("user_id", req.user.id)
    .order("last_seen_at", { ascending: false })
    .limit(20);

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  const sessions = (data || []).map((session) => ({
    ...session,
    current: session.id === currentSessionId
  }));

  return res.json({
    ok: true,
    sessions
  });
});

app.delete("/api/sessions/:id", requireAuth, requireMfaIfEnabled, async (req, res) => {
  const currentSessionId = req.cookies.lk_session_id;

  if (req.params.id === currentSessionId) {
    return res.status(400).json({
      ok: false,
      error: "Você não pode revogar a sessão atual por esta rota. Use logout."
    });
  }

  const { error } = await db
    .from("account_sessions")
    .update({
      revoked: true,
      current: false,
      last_seen_at: new Date().toISOString()
    })
    .eq("id", req.params.id)
    .eq("user_id", req.user.id);

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  await logEvent(req, {
    action: "session.revoked",
    target: "auth.session",
    metadata: {
      sessionId: req.params.id
    }
  });

  return res.json({ ok: true });
});

app.post("/api/sessions/revoke-all-others", requireAuth, requireMfaIfEnabled, async (req, res) => {
  const currentSessionId = req.cookies.lk_session_id;

  const { error } = await db
    .from("account_sessions")
    .update({
      revoked: true,
      current: false,
      last_seen_at: new Date().toISOString()
    })
    .eq("user_id", req.user.id)
    .neq("id", currentSessionId);

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  await logEvent(req, {
    action: "session.revoked_all_others",
    target: "auth.session"
  });

  return res.json({ ok: true });
});

/* =========================
   AUDIT LOGS
========================= */

app.get("/api/audit-logs", requireAuth, requireMfaIfEnabled, async (req, res) => {
  const { data, error } = await db
    .from("audit_logs")
    .select("id, action, target, metadata, created_at")
    .eq("user_id", req.user.id)
    .order("created_at", { ascending: false })
    .limit(50);

  if (error) {
    return res.status(400).json({
      ok: false,
      error: error.message
    });
  }

  return res.json({
    ok: true,
    logs: data || []
  });
});

/* =========================
   FALLBACK
========================= */

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      ok: false,
      error: "api_route_not_found"
    });
  }

  return res.status(404).json({
    ok: false,
    error: "route_not_found"
  });
});

app.listen(PORT, () => {
  console.log(`Lukintosh Accounts Auth Service running on port ${PORT}`);
  console.log(`Frontend: ${PUBLIC_SITE_URL}`);
  console.log(`API/Auth: ${API_BASE_URL}`);
  console.log(`Cookie domain: ${COOKIE_DOMAIN || "host-only"}`);
  console.log(`Email enabled: ${Boolean(resend)}`);
});
