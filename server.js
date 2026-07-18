import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";
import QRCode from "qrcode";
import { Resend } from "resend";
import WebSocket from "ws";

dotenv.config();

if (!globalThis.WebSocket) {
  globalThis.WebSocket = WebSocket;
}

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

const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || ".lukintosh.com";

const RESEND_API_KEY = process.env.RESEND_API_KEY || null;
const OIDC_ISSUER = process.env.OIDC_ISSUER || API_BASE_URL;
const OIDC_KEY_ID = process.env.OIDC_KEY_ID || "lukintosh-auth-dev";
const DIDIT_BASE_URL = process.env.DIDIT_BASE_URL || "https://verification.didit.me";
const DIDIT_API_KEY = process.env.DIDIT_API_KEY || null;
const DIDIT_FACE_WORKFLOW_ID = process.env.DIDIT_FACE_WORKFLOW_ID || process.env.DIDIT_WORKFLOW_ID || null;
const DIDIT_DOCUMENT_WORKFLOW_ID = process.env.DIDIT_DOCUMENT_WORKFLOW_ID || null;
const DIDIT_AGE_WORKFLOW_ID = process.env.DIDIT_AGE_WORKFLOW_ID || null;
const DIDIT_ADAPTIVE_AGE_WORKFLOW_ID = process.env.DIDIT_ADAPTIVE_AGE_WORKFLOW_ID || null;
const DIDIT_WEBHOOK_SECRET = process.env.DIDIT_WEBHOOK_SECRET || null;

const EMAIL_FROM =
  process.env.EMAIL_FROM || "Lukintosh Accounts <security@lukintosh.com>";

const EMAIL_REPLY_TO =
  process.env.EMAIL_REPLY_TO || "security@lukintosh.com";

const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;
const fallbackKeyPair = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048
});

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_ANON_KEY");
  process.exit(1);
}

if (!SUPABASE_SERVICE_ROLE_KEY) {
  console.warn("SUPABASE_SERVICE_ROLE_KEY is missing. Database writes may fail.");
}

/* =========================
   SUPABASE CLIENTS
========================= */

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

/* =========================
   APP SETUP
========================= */

const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3010",
  "http://localhost:5173",
  "http://localhost:5500",
  "http://localhost:5501",
  "http://localhost:8000",
  "http://localhost:8080",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:3010",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5500",
  "http://127.0.0.1:5501",
  "http://127.0.0.1:8000",
  "http://127.0.0.1:8080",
  "https://lukintosh.com",
  "https://www.lukintosh.com",
  "https://myaccount.lukintosh.com",
  "https://auth.lukintosh.com",
  "https://developer.lukintosh.com",
  "https://support.lukintosh.com",
  "https://store.lukintosh.com",
  "https://cloud.lukintosh.com",
  "https://accounts.lukintosh.com",
  PUBLIC_SITE_URL,
  API_BASE_URL
];

const ALLOWED_RETURN_ORIGINS = new Set([
  "https://lukintosh.com",
  "https://www.lukintosh.com",
  "https://myaccount.lukintosh.com",
  "https://auth.lukintosh.com",
  "https://developer.lukintosh.com",
  "https://support.lukintosh.com",
  "https://store.lukintosh.com",
  "https://cloud.lukintosh.com",
  "https://accounts.lukintosh.com"
]);

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

function shortenDiditFloats(value) {
  if (Array.isArray(value)) return value.map(shortenDiditFloats);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, shortenDiditFloats(item)])
    );
  }
  return typeof value === "number" && Number.isInteger(value) ? Math.trunc(value) : value;
}

function sortDiditKeys(value) {
  if (Array.isArray(value)) return value.map(sortDiditKeys);
  if (value !== null && typeof value === "object") {
    return Object.keys(value).sort().reduce((sorted, key) => {
      sorted[key] = sortDiditKeys(value[key]);
      return sorted;
    }, {});
  }
  return value;
}

function verifyDiditSignature(rawBody, signature, timestamp) {
  if (!DIDIT_WEBHOOK_SECRET || !signature || !timestamp) return false;
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false;

  let parsed;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return false;
  }

  const canonical = JSON.stringify(sortDiditKeys(shortenDiditFloats(parsed)));
  const expected = crypto
    .createHmac("sha256", DIDIT_WEBHOOK_SECRET)
    .update(canonical, "utf8")
    .digest("hex");
  const expectedBuffer = Buffer.from(expected, "utf8");
  const signatureBuffer = Buffer.from(String(signature), "utf8");

  return (
    expectedBuffer.length === signatureBuffer.length &&
    crypto.timingSafeEqual(expectedBuffer, signatureBuffer)
  );
}

function mapDiditStatus(value) {
  const status = String(value || "").toLowerCase();
  if (status === "approved") return "verified";
  if (["declined", "abandoned", "expired", "kyc expired"].includes(status)) return "failed";
  if (["in progress", "in review", "resubmitted", "awaiting user"].includes(status)) return "processing";
  return "not_started";
}

app.post(
  "/api/webhooks/didit/identity",
  express.raw({ type: "application/json", limit: "2mb" }),
  async (req, res) => {
    if (!DIDIT_API_KEY || !DIDIT_WEBHOOK_SECRET) {
      return res.status(503).send("Webhook not configured");
    }

    const rawBody = Buffer.isBuffer(req.body) ? req.body.toString("utf8") : "";
    if (!verifyDiditSignature(
      rawBody,
      req.headers["x-signature-v2"],
      req.headers["x-timestamp"]
    )) {
      return res.status(401).send("Invalid signature");
    }

    let event;
    try {
      event = JSON.parse(rawBody);
    } catch {
      return res.status(400).send("Invalid payload");
    }

    const sessionId = event.session_id;
    const userId = event.vendor_data;
    const status = mapDiditStatus(event.status || event.decision?.status);
    if (!sessionId || !userId) return res.json({ received: true });

    try {
      const { data: currentData, error: currentError } = await db.auth.admin.getUserById(userId);
      if (currentError || !currentData.user) return res.status(404).send("User not found");

      const identityVerifications = getIdentityVerifications(currentData.user);
      const currentIdentity = Object.values(identityVerifications).find(
        (verification) => verification.sessionId === sessionId
      );
      if (!currentIdentity) return res.status(409).send("Session does not belong to user");
      if (currentIdentity.status === "verified" && status !== "verified") return res.json({ received: true });

      const eventDate = event.created_at
        ? new Date(event.created_at * 1000).toISOString()
        : new Date().toISOString();
      await updateIdentityVerification(userId, {
        provider: "didit",
        type: event.metadata?.verification_type || currentIdentity.type,
        status,
        sessionId,
        createdAt: currentIdentity.createdAt,
        lastUpdatedAt: eventDate,
        completedAt: status === "verified" ? eventDate : currentIdentity.completedAt
      });

      return res.json({ received: true });
    } catch {
      return res.status(500).send("Webhook processing failed");
    }
  }
);

app.use(express.json({ limit: "25mb" }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
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

/* =========================
   EMAIL CODE STORE
========================= */

const emailLoginChallenges = new Map();

function cleanupEmailChallenges() {
  const now = Date.now();

  for (const [id, challenge] of emailLoginChallenges.entries()) {
    if (challenge.expiresAt <= now || challenge.used) {
      emailLoginChallenges.delete(id);
    }
  }
}

setInterval(cleanupEmailChallenges, 1000 * 60 * 5).unref();

/* =========================
   HELPERS
========================= */

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
    secure: true,
    sameSite: "none",
    path: "/",
    domain: COOKIE_DOMAIN,
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

const DEFAULT_OAUTH_SCOPES = ["openid", "profile", "email"];
const ALLOWED_OAUTH_SCOPES = new Set(DEFAULT_OAUTH_SCOPES);

function generateOpaqueToken(prefix, byteLength = 32) {
  return `${prefix}_${crypto.randomBytes(byteLength).toString("base64url")}`;
}

function normalizeScopes(value) {
  const source = Array.isArray(value)
    ? value
    : String(value || DEFAULT_OAUTH_SCOPES.join(" ")).split(/[,\s]+/);

  const scopes = source
    .map((scope) => String(scope || "").trim().toLowerCase())
    .filter(Boolean);

  const unique = [...new Set(scopes.length ? scopes : DEFAULT_OAUTH_SCOPES)];

  return unique.filter((scope) => ALLOWED_OAUTH_SCOPES.has(scope));
}

function normalizeRedirectUris(value) {
  const source = Array.isArray(value) ? value : [value];

  return source
    .map((uri) => String(uri || "").trim())
    .filter(Boolean)
    .map((uri) => {
      const parsed = new URL(uri);

      const isLocalhost =
        parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";

      if (parsed.protocol !== "https:" && !(isLocalhost && parsed.protocol === "http:")) {
        throw new Error("redirect_uri_must_use_https");
      }

      parsed.hash = "";
      return parsed.toString();
    });
}

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function getPrivateKeyPem() {
  const configuredPem = process.env.OIDC_PRIVATE_KEY_PEM?.replace(/\\n/g, "\n");

  if (configuredPem) {
    try {
      crypto.createPrivateKey(configuredPem);
      return configuredPem;
    } catch {
      console.warn("OIDC_PRIVATE_KEY_PEM is invalid. Using runtime fallback key.");
    }
  }

  return fallbackKeyPair.privateKey.export({ type: "pkcs8", format: "pem" });
}

function getPublicKeyObject() {
  const publicPem = process.env.OIDC_PUBLIC_KEY_PEM?.replace(/\\n/g, "\n");

  if (publicPem) {
    try {
      return crypto.createPublicKey(publicPem);
    } catch {
      console.warn("OIDC_PUBLIC_KEY_PEM is invalid. Trying private key public export.");
    }
  }

  try {
    return crypto.createPublicKey(getPrivateKeyPem());
  } catch {
    return fallbackKeyPair.publicKey;
  }
}

function signJwt(payload, expiresInSeconds = 3600) {
  const now = Math.floor(Date.now() / 1000);
  const header = {
    alg: "RS256",
    typ: "JWT",
    kid: OIDC_KEY_ID
  };

  const body = {
    iss: OIDC_ISSUER,
    iat: now,
    exp: now + expiresInSeconds,
    ...payload
  };

  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(body)}`;
  const signature = crypto
    .createSign("RSA-SHA256")
    .update(signingInput)
    .sign(getPrivateKeyPem(), "base64url");

  return `${signingInput}.${signature}`;
}

function verifyJwt(token) {
  const [header, payload, signature] = String(token || "").split(".");

  if (!header || !payload || !signature) {
    throw new Error("invalid_token");
  }

  const ok = crypto
    .createVerify("RSA-SHA256")
    .update(`${header}.${payload}`)
    .verify(getPublicKeyObject(), signature, "base64url");

  if (!ok) throw new Error("invalid_token");

  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));

  if (claims.exp && claims.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("token_expired");
  }

  return claims;
}

function pkceS256(verifier) {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

function timingSafeEqualText(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));

  if (left.length !== right.length) return false;

  return crypto.timingSafeEqual(left, right);
}

function getClientSecretFromRequest(req) {
  const authorization = String(req.headers.authorization || "");

  if (authorization.startsWith("Basic ")) {
    const decoded = Buffer.from(authorization.slice("Basic ".length), "base64")
      .toString("utf8");
    const [clientId, clientSecret] = decoded.split(":");
    return {
      clientId,
      clientSecret
    };
  }

  return {
    clientId: req.body.client_id,
    clientSecret: req.body.client_secret
  };
}

function hashCode(code) {
  return crypto
    .createHash("sha256")
    .update(`${LOG_HASH_SECRET}:email-code:${code}`)
    .digest("hex");
}

function generateSixDigitCode() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
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

  res.cookie("lukintosh_session", session.access_token, {
    ...cookieOptions,
    maxAge: 1000 * 60 * 60
  });

  res.cookie("lukintosh_refresh", session.refresh_token, {
    ...cookieOptions,
    maxAge: 1000 * 60 * 60 * 24 * 30
  });
}

function clearAuthCookies(res) {
  const options = getCookieOptions();

  const cookieNames = [
    "lk_access_token",
    "lk_refresh_token",
    "lk_session_id",
    "lk_oauth_return_to",
    "lukintosh_session",
    "lukintosh_refresh"
  ];

  for (const name of cookieNames) {
    res.clearCookie(name, options);

    res.cookie(name, "", {
      ...options,
      maxAge: 0,
      expires: new Date(0)
    });
  }
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
    req.cookies.lk_oauth_return_to ||
      req.query.returnTo ||
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
    apple: "Apple",
    oauth: "OAuth"
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
  const identityVerification = getIdentityVerification(user);

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

    identityVerification,

    createdAt: user.created_at,
    lastSignInAt: user.last_sign_in_at,
    emailConfirmedAt: user.email_confirmed_at
  };
}

function emptyIdentityVerification(type = "face") {
  return {
    status: "not_started",
    verified: false,
    provider: null,
    type,
    sessionId: null,
    createdAt: null,
    completedAt: null,
    lastUpdatedAt: null,
  };
}

function getIdentityVerification(user, type = "face") {
  const metadata = user?.user_metadata || {};
  const storedVerifications = metadata.identity_verifications;
  const legacyValue = metadata.identity_verification;
  const value = storedVerifications?.[type] || (type === "face" ? legacyValue : null);

  if (!value || typeof value !== "object") {
    return emptyIdentityVerification(type);
  }

  return {
    status: value.status || "not_started",
    verified: value.status === "verified",
    provider: value.provider || null,
    type: value.verification_type || value.type || type,
    sessionId: value.session_id || value.sessionId || null,
    createdAt: value.created_at || value.createdAt || null,
    completedAt: value.completed_at || value.completedAt || null,
    lastUpdatedAt: value.last_updated_at || value.lastUpdatedAt || null
  };
}

function getIdentityVerifications(user) {
  return {
    face: getIdentityVerification(user, "face"),
    document: getIdentityVerification(user, "document"),
    age: getIdentityVerification(user, "age"),
    adaptive_age: getIdentityVerification(user, "adaptive_age")
  };
}

async function updateIdentityVerification(userId, verification) {
  if (!SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("supabase_service_role_required");
  }

  const { data: currentData, error: currentError } =
    await db.auth.admin.getUserById(userId);

  if (currentError) throw currentError;

  const currentMetadata = currentData.user?.user_metadata || {};
  const type = verification.type || verification.verificationType || "face";
  const currentVerifications = getIdentityVerifications(currentData.user);
  const storedVerification = {
    provider: verification.provider || "didit",
    verification_type: type,
    status: verification.status,
    session_id: verification.sessionId,
    created_at: verification.createdAt || null,
    completed_at: verification.completedAt || null,
    last_updated_at: verification.lastUpdatedAt || new Date().toISOString(),
  };

  const { data, error } = await db.auth.admin.updateUserById(userId, {
    user_metadata: {
      ...currentMetadata,
      identity_verification: type === "face"
        ? storedVerification
        : currentMetadata.identity_verification || {
            provider: currentVerifications.face.provider,
            verification_type: "face",
            status: currentVerifications.face.status,
            session_id: currentVerifications.face.sessionId,
            created_at: currentVerifications.face.createdAt,
            completed_at: currentVerifications.face.completedAt,
            last_updated_at: currentVerifications.face.lastUpdatedAt
          },
      identity_verifications: {
        ...currentMetadata.identity_verifications,
        [type]: storedVerification
      }
    }
  });

  if (error) throw error;

  return data.user;
}

async function diditRequest(path, options = {}) {
  if (!DIDIT_API_KEY) {
    const error = new Error("didit_identity_not_configured");
    error.status = 503;
    throw error;
  }

  const response = await fetch(`${DIDIT_BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "x-api-key": DIDIT_API_KEY,
      ...(options.headers || {})
    }
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok || data.status === "fail") {
    const error = new Error(data.detail || data.message || "didit_request_failed");
    error.status = response.status || 502;
    error.payload = data;
    throw error;
  }

  return data;
}

function mapDiditSession(session) {
  const rawStatus = session?.status || session?.decision?.status || "Not Started";
  const status = mapDiditStatus(rawStatus);

  return {
    provider: "didit",
    status,
    verified: status === "verified",
    sessionId: session.session_id || session.id || null,
    createdAt: session.created_at || new Date().toISOString(),
    completedAt: status === "verified"
      ? session.completed_at || new Date().toISOString()
      : null,
    lastUpdatedAt: new Date().toISOString()
  };
}

/* =========================
   EMAILS
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

async function sendLoginCodeEmail({ user, code }) {
  if (!user?.email) return { skipped: true };

  const html = getSecurityEmailBase({
    title: "Seu código Lukintosh",
    preview: `Seu código de verificação é ${code}.`,
    body: `
      <p style="margin:0 0 18px;color:#d9d9df;line-height:1.6;font-size:15px;">
        Use o código abaixo para concluir seu login no Lukintosh Accounts.
      </p>

      <div style="margin:20px 0;border:1px solid rgba(255,255,255,.12);border-radius:24px;padding:22px;background:rgba(255,255,255,.05);text-align:center;">
        <p style="margin:0 0 8px;color:#a6a6ad;font-size:13px;">Código de verificação</p>
        <p style="margin:0;color:#f5f5f7;font-size:42px;letter-spacing:8px;font-weight:900;">
          ${escapeHtml(code)}
        </p>
      </div>

      <p style="margin:0;color:#a6a6ad;line-height:1.6;font-size:14px;">
        Este código expira em 10 minutos. Se você não tentou entrar, ignore este e-mail e revise a segurança da sua conta.
      </p>
    `
  });

  return sendEmail({
    to: user.email,
    subject: `Seu código Lukintosh Accounts é ${code}`,
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
  const accessToken =
    req.cookies.lk_access_token ||
    req.cookies.lukintosh_session ||
    null;

  const refreshToken =
    req.cookies.lk_refresh_token ||
    req.cookies.lukintosh_refresh ||
    null;

  const internalSessionId = req.cookies.lk_session_id || null;

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
    const authorization = req.headers.authorization || "";

    const bearerToken = authorization.startsWith("Bearer ")
      ? authorization.slice("Bearer ".length).trim()
      : null;

    if (bearerToken && bearerToken !== "null" && bearerToken !== "undefined") {
      const { data, error } = await supabase.auth.getUser(bearerToken);

      if (!error && data.user) {
        req.user = data.user;
        req.accessToken = bearerToken;
        return next();
      }
    }

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
    cookieMode: "global-lukintosh-cookie",
    nodeEnv: process.env.NODE_ENV || null,
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
    cookieMode: "global-lukintosh-cookie",
    nodeEnv: process.env.NODE_ENV || null,
    emailEnabled: Boolean(resend),
    emailFrom: EMAIL_FROM
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
        redirectTo: `${callbackBaseUrl}/auth/callback`,
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
      user: data.user ? publicUser(data.user) : null,
      session: data.session
        ? {
            accessToken: data.session.access_token,
            refreshToken: data.session.refresh_token,
            expiresAt: data.session.expires_at
          }
        : null
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

    const code = generateSixDigitCode();
    const challengeId = crypto.randomUUID();

    emailLoginChallenges.set(challengeId, {
      id: challengeId,
      userId: data.user.id,
      email: data.user.email,
      codeHash: hashCode(code),
      attempts: 0,
      maxAttempts: 5,
      expiresAt: Date.now() + 1000 * 60 * 10,
      used: false,
      session: data.session,
      user: data.user
    });

    const emailResult = await sendLoginCodeEmail({
      user: data.user,
      code
    });

    if (emailResult?.error) {
      emailLoginChallenges.delete(challengeId);

      return res.status(500).json({
        ok: false,
        error: "email_code_send_failed"
      });
    }

    await logEvent(req, {
      userId: data.user.id,
      action: "account.login_code_sent",
      target: "auth.user",
      metadata: {
        email: data.user.email
      }
    });

    return res.json({
      ok: true,
      emailCodeRequired: true,
      challengeId,
      message: "Código enviado para seu e-mail."
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      ok: false,
      error: "internal_server_error"
    });
  }
});

app.post("/api/login/verify-code", async (req, res) => {
  try {
    const { challengeId, code } = req.body;

    if (!challengeId || !code) {
      return res.status(400).json({
        ok: false,
        error: "challenge_id_and_code_required"
      });
    }

    const challenge = emailLoginChallenges.get(challengeId);

    if (!challenge || challenge.used || challenge.expiresAt <= Date.now()) {
      return res.status(400).json({
        ok: false,
        error: "invalid_code"
      });
    }

    if (challenge.attempts >= challenge.maxAttempts) {
      emailLoginChallenges.delete(challengeId);

      return res.status(400).json({
        ok: false,
        error: "too_many_code_attempts"
      });
    }

    challenge.attempts += 1;

    if (hashCode(String(code).trim()) !== challenge.codeHash) {
      return res.status(400).json({
        ok: false,
        error: "invalid_code"
      });
    }

    challenge.used = true;
    emailLoginChallenges.delete(challengeId);

    await registerDeviceAndSession(req, res, challenge.user, challenge.session);

    req.user = challenge.user;
    req.accessToken = challenge.session.access_token;

    const mfa = await getMfaState(challenge.session.access_token).catch(() => null);

    sendNewLoginEmail({
      user: challenge.user,
      req,
      providerLabel: "E-mail e senha"
    }).catch((emailError) => {
      console.warn("Password login email failed:", emailError.message);
    });

    await logEvent(req, {
      userId: challenge.user.id,
      action: "account.login",
      target: "auth.user",
      metadata: {
        method: "email_password_code",
        mfaRequired: Boolean(mfa?.needsChallenge)
      }
    });

    return res.json({
      ok: true,
      user: publicUser(challenge.user),
      mfaRequired: Boolean(mfa?.needsChallenge),
      mfa,
      session: {
        accessToken: challenge.session.access_token,
        refreshToken: challenge.session.refresh_token,
        expiresAt: challenge.session.expires_at
      }
    });
  } catch (error) {
    console.error("Verify login code error:", error);

    return res.status(500).json({
      ok: false,
      error: "internal_server_error"
    });
  }
});

app.post("/api/logout", async (req, res) => {
  try {
    const cookieAccessToken =
      req.cookies.lk_access_token ||
      req.cookies.lukintosh_session ||
      null;

    const authorization = req.headers.authorization || "";

    const bearerToken = authorization.startsWith("Bearer ")
      ? authorization.slice("Bearer ".length).trim()
      : null;

    const accessToken = cookieAccessToken || bearerToken;
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
   MFA / 2FA
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

app.get("/api/identity/status", requireAuth, async (req, res) => {
  try {
    const { data: currentData, error: currentError } =
      SUPABASE_SERVICE_ROLE_KEY
        ? await db.auth.admin.getUserById(req.user.id)
        : { data: { user: req.user }, error: null };

    if (currentError) {
      return res.status(400).json({
        ok: false,
        error: currentError.message
      });
    }

    const currentUser = currentData.user || req.user;
    const requestedType = String(req.query.type || "face");
    const type = ["face", "document", "age", "adaptive_age"].includes(requestedType)
      ? requestedType
      : "face";
    let identityVerification = getIdentityVerification(currentUser, type);

    if (
      DIDIT_API_KEY &&
      identityVerification.sessionId &&
      identityVerification.status !== "verified" &&
      identityVerification.status !== "failed"
    ) {
      const decision = await diditRequest(
        `/v3/session/${encodeURIComponent(identityVerification.sessionId)}/decision/`
      );

      identityVerification = {
        ...mapDiditSession(decision),
        type
      };
      await updateIdentityVerification(req.user.id, identityVerification);
    }

    return res.json({
      ok: true,
      enabled: Boolean(
        DIDIT_API_KEY &&
        getDiditWorkflowId(type) &&
        DIDIT_WEBHOOK_SECRET &&
        SUPABASE_SERVICE_ROLE_KEY
      ),
      identityVerification
    });
  } catch (error) {
    console.error("Identity status error");

    return res.status(error.status || 500).json({
      ok: false,
      error: error.message || "identity_status_failed"
    });
  }
});

function getDiditWorkflowId(type) {
  return {
    face: DIDIT_FACE_WORKFLOW_ID,
    document: DIDIT_DOCUMENT_WORKFLOW_ID,
    age: DIDIT_AGE_WORKFLOW_ID,
    adaptive_age: DIDIT_ADAPTIVE_AGE_WORKFLOW_ID
  }[type] || null;
}

async function startDiditIdentity(req, res, type) {
  try {
    const workflowId = getDiditWorkflowId(type);

    if (!DIDIT_API_KEY || !workflowId) {
      return res.status(503).json({
        ok: false,
        error: "didit_identity_not_configured"
      });
    }

    if (!SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(503).json({
        ok: false,
        error: "supabase_service_role_required"
      });
    }

    const body = JSON.stringify({
      workflow_id: workflowId,
      vendor_data: req.user.id,
      callback: getFrontendUrl("?identity=return"),
      callback_method: "both",
      language: "pt",
      metadata: { verification_type: type }
    });
    const response = await fetch(`${DIDIT_BASE_URL}/v3/session/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": DIDIT_API_KEY
      },
      body
    });
    const responseText = await response.text();
    let session = {};
    try {
      session = responseText ? JSON.parse(responseText) : {};
    } catch {
      session = {};
    }

    if (!response.ok || !session.session_id || !session.url) {
      const workflowError = Array.isArray(session.workflow_id)
        ? session.workflow_id[0]
        : session.workflow_id;
      const providerError =
        session.detail ||
        session.message ||
        workflowError ||
        `didit_session_creation_failed_${response.status || "unknown"}`;
      const error = new Error(providerError);
      error.status = response.status || 502;
      throw error;
    }

    const identityVerification = {
      ...mapDiditSession(session),
      type
    };
    const updatedUser = await updateIdentityVerification(req.user.id, identityVerification);

    await logEvent(req, {
      action: "identity.verification_started",
      target: "didit.identity.verification_session",
      metadata: {
        sessionId: identityVerification.sessionId,
        status: identityVerification.status,
        type
      }
    });

    return res.json({
      ok: true,
      url: session.url,
      identityVerification,
      user: publicUser(updatedUser)
    });
  } catch (error) {
    console.error("Identity start error");

    return res.status(error.status || 500).json({
      ok: false,
      error: error.message || "identity_start_failed",
      message: error.message || "identity_start_failed"
    });
  }
}

app.post("/api/identity/start", requireAuth, requireMfaIfEnabled, async (req, res) => {
  const requestedType = String(req.body?.type || "face");
  const type = ["face", "document", "age", "adaptive_age"].includes(requestedType)
    ? requestedType
    : "face";
  return startDiditIdentity(req, res, type);
});

app.post("/api/identity/start-face", requireAuth, requireMfaIfEnabled, async (req, res) => {
  return startDiditIdentity(req, res, "face");
});

app.post("/api/identity/start-document", requireAuth, requireMfaIfEnabled, async (req, res) => {
  return startDiditIdentity(req, res, "document");
});

app.post("/api/identity/start-age", requireAuth, requireMfaIfEnabled, async (req, res) => {
  return startDiditIdentity(req, res, "age");
});

app.post("/api/identity/start-adaptive-age", requireAuth, requireMfaIfEnabled, async (req, res) => {
  return startDiditIdentity(req, res, "adaptive_age");
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

  const identityVerification = getIdentityVerification(req.user);

  const securityChecks = {
    emailVerified: Boolean(req.user.email_confirmed_at),
    identityVerified: Boolean(
      identityVerification.verified && identityVerification.type === "face"
    ),
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
      identityVerification,
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
   OAUTH 2.1 / OPENID CONNECT
========================= */

app.get("/.well-known/openid-configuration", (req, res) => {
  return res.json({
    issuer: OIDC_ISSUER,
    authorization_endpoint: `${OIDC_ISSUER}/oauth/authorize`,
    token_endpoint: `${OIDC_ISSUER}/oauth/token`,
    userinfo_endpoint: `${OIDC_ISSUER}/oauth/userinfo`,
    jwks_uri: `${OIDC_ISSUER}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: DEFAULT_OAUTH_SCOPES,
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"]
  });
});

app.get("/.well-known/jwks.json", (req, res) => {
  const jwk = getPublicKeyObject().export({ format: "jwk" });

  return res.json({
    keys: [
      {
        ...jwk,
        kid: OIDC_KEY_ID,
        alg: "RS256",
        use: "sig"
      }
    ]
  });
});

async function getActiveOAuthClient(clientId) {
  const { data, error } = await db
    .from("oauth_clients")
    .select("id, client_id, client_secret_hash, name, redirect_uris, allowed_scopes, is_active")
    .eq("client_id", clientId)
    .eq("is_active", true)
    .single();

  if (error || !data) return null;

  return data;
}

app.get("/oauth/authorize", async (req, res) => {
  try {
    const clientId = String(req.query.client_id || "");
    const redirectUri = String(req.query.redirect_uri || "");
    const responseType = String(req.query.response_type || "");
    const state = String(req.query.state || "");
    const codeChallenge = String(req.query.code_challenge || "");
    const codeChallengeMethod = String(req.query.code_challenge_method || "");
    const requestedScopes = normalizeScopes(req.query.scope || "openid");

    if (responseType !== "code") {
      return res.status(400).send("response_type must be code");
    }

    if (!clientId || !redirectUri || !codeChallenge || codeChallengeMethod !== "S256") {
      return res.status(400).send("Missing required OAuth 2.1 PKCE parameters");
    }

    const client = await getActiveOAuthClient(clientId);

    if (!client) {
      return res.status(400).send("Unknown OAuth client");
    }

    if (!client.redirect_uris?.includes(redirectUri)) {
      return res.status(400).send("redirect_uri does not match registered callback");
    }

    const allowedScopes = new Set(client.allowed_scopes || DEFAULT_OAUTH_SCOPES);
    const scopes = requestedScopes.filter((scope) => allowedScopes.has(scope));

    if (!scopes.length) {
      return res.status(400).send("Invalid OAuth scope");
    }

    const auth = await refreshSessionIfNeeded(req, res);

    if (!auth) {
      return res.redirect(
        getFrontendUrl(`?returnTo=${encodeURIComponent(req.originalUrl.startsWith("http") ? req.originalUrl : getApiUrl(req.originalUrl))}`)
      );
    }

    const scopeItems = scopes
      .map((scope) => `<li>${escapeHtml(getScopeLabel(scope))}</li>`)
      .join("");

    return res.send(`
      <!doctype html>
      <html lang="pt-BR">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>Entrar com Lukintosh</title>
          <style>
            * { box-sizing: border-box; }
            body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #050507; color: #f5f5f7; font-family: Inter, Arial, sans-serif; padding: 22px; }
            .card { width: min(480px, 100%); padding: 30px; border-radius: 30px; background: rgba(255,255,255,.075); border: 1px solid rgba(255,255,255,.14); box-shadow: 0 30px 90px rgba(0,0,0,.48); }
            .logo { width: 44px; height: 44px; border-radius: 15px; background: linear-gradient(145deg,#fff,#8ab4ff 45%,#b49cff); margin-bottom: 18px; }
            h1 { margin: 0 0 10px; font-size: 29px; line-height: 1; letter-spacing: -1px; }
            p { color: #b9b9c4; line-height: 1.55; margin: 10px 0; }
            .app-box { margin: 20px 0; padding: 16px; border-radius: 20px; background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.1); }
            .app-name { font-size: 18px; font-weight: 850; }
            .uri { margin-top: 8px; color: #8e8e99; font-size: 12px; overflow-wrap: anywhere; }
            ul { margin: 12px 0 20px; padding-left: 20px; color: #e5e8ff; line-height: 1.7; }
            button { width: 100%; border: 0; border-radius: 999px; padding: 14px 18px; margin-top: 10px; font-weight: 850; cursor: pointer; font-size: 15px; }
            .approve { background: #f5f5f7; color: #050507; }
            .deny { background: rgba(255,255,255,.12); color: #f5f5f7; }
          </style>
        </head>
        <body>
          <main class="card">
            <div class="logo"></div>
            <h1>Entrar com Lukintosh</h1>
            <p>Revise a solicitação antes de continuar.</p>
            <div class="app-box">
              <div class="app-name">${escapeHtml(client.name)}</div>
              <div class="uri">${escapeHtml(redirectUri)}</div>
            </div>
            <p>Este app quer acessar:</p>
            <ul>${scopeItems}</ul>
            <form method="post" action="/oauth/authorize/decision">
              <input type="hidden" name="decision" value="approve" />
              <input type="hidden" name="client_id" value="${escapeHtml(clientId)}" />
              <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}" />
              <input type="hidden" name="scope" value="${escapeHtml(scopes.join(" "))}" />
              <input type="hidden" name="state" value="${escapeHtml(state)}" />
              <input type="hidden" name="code_challenge" value="${escapeHtml(codeChallenge)}" />
              <button class="approve" type="submit">Continuar com Lukintosh</button>
            </form>
            <form method="post" action="/oauth/authorize/decision">
              <input type="hidden" name="decision" value="deny" />
              <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}" />
              <input type="hidden" name="state" value="${escapeHtml(state)}" />
              <button class="deny" type="submit">Cancelar</button>
            </form>
          </main>
        </body>
      </html>
    `);
  } catch (error) {
    return res.status(400).send(escapeHtml(error.message || "invalid_authorization_request"));
  }
});

app.post("/oauth/authorize/decision", requireAuth, async (req, res) => {
  const redirectUri = String(req.body.redirect_uri || "");
  const state = String(req.body.state || "");
  const destination = new URL(redirectUri);

  if (state) destination.searchParams.set("state", state);

  if (req.body.decision !== "approve") {
    destination.searchParams.set("error", "access_denied");
    return res.redirect(destination.toString());
  }

  const client = await getActiveOAuthClient(String(req.body.client_id || ""));

  if (!client || !client.redirect_uris?.includes(redirectUri)) {
    return res.status(400).send("Invalid OAuth client or redirect_uri");
  }

  const code = generateOpaqueToken("lk_code", 32);
  const expiresAt = new Date(Date.now() + 1000 * 60 * 5).toISOString();
  const approvedScope = String(req.body.scope || "openid");
  const approvedScopes = approvedScope.split(" ").filter(Boolean);

  const { error } = await db
    .from("oauth_authorization_codes")
    .insert({
      code_hash: hashValue(code),
      client_id: client.client_id,
      user_id: req.user.id,
      redirect_uri: redirectUri,
      scope: approvedScope,
      scopes: approvedScopes,
      code_challenge: String(req.body.code_challenge || ""),
      code_challenge_method: "S256",
      expires_at: expiresAt
    });

  if (error) {
    return res.status(400).send(escapeHtml(error.message));
  }

  destination.searchParams.set("code", code);
  return res.redirect(destination.toString());
});

app.post("/oauth/token", async (req, res) => {
  try {
    const grantType = String(req.body.grant_type || "");
    const code = String(req.body.code || "");
    const redirectUri = String(req.body.redirect_uri || "");
    const codeVerifier = String(req.body.code_verifier || "");
    const { clientId, clientSecret } = getClientSecretFromRequest(req);

    if (grantType !== "authorization_code") {
      return res.status(400).json({ error: "unsupported_grant_type" });
    }

    const client = await getActiveOAuthClient(String(clientId || ""));

    if (!client || !client.client_secret_hash || hashValue(clientSecret) !== client.client_secret_hash) {
      return res.status(401).json({ error: "invalid_client" });
    }

    const { data: authCode, error } = await db
      .from("oauth_authorization_codes")
      .select("*")
      .eq("code_hash", hashValue(code))
      .eq("client_id", client.client_id)
      .is("used_at", null)
      .single();

    if (error || !authCode) {
      return res.status(400).json({ error: "invalid_grant" });
    }

    if (new Date(authCode.expires_at).getTime() <= Date.now()) {
      return res.status(400).json({ error: "invalid_grant", error_description: "authorization_code_expired" });
    }

    if (authCode.redirect_uri !== redirectUri) {
      return res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri_mismatch" });
    }

    if (!timingSafeEqualText(pkceS256(codeVerifier), authCode.code_challenge)) {
      return res.status(400).json({ error: "invalid_grant", error_description: "pkce_verification_failed" });
    }

    const { error: consumeError } = await db
      .from("oauth_authorization_codes")
      .update({ used_at: new Date().toISOString() })
      .eq("id", authCode.id)
      .is("used_at", null);

    if (consumeError) {
      return res.status(400).json({ error: "invalid_grant" });
    }

    const { data: userData } = await db.auth.admin.getUserById(authCode.user_id);
    const user = userData?.user;

    if (!user) {
      return res.status(400).json({ error: "invalid_grant" });
    }

    const scopes = String(authCode.scope || "openid").split(" ").filter(Boolean);
    const accessToken = signJwt({
      sub: user.id,
      aud: client.client_id,
      client_id: client.client_id,
      scope: scopes.join(" "),
      token_use: "access"
    });

    const response = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: scopes.join(" ")
    };

    if (scopes.includes("openid")) {
      response.id_token = signJwt({
        sub: user.id,
        aud: client.client_id,
        email: scopes.includes("email") ? user.email : undefined,
        name: scopes.includes("profile") ? publicUser(user).displayName : undefined,
        picture: scopes.includes("profile") ? publicUser(user).avatarUrl : undefined,
        token_use: "id"
      });
    }

    db.from("oauth_tokens").insert({
      token_jti_hash: hashValue(accessToken),
      token_hash: hashValue(accessToken),
      client_id: client.client_id,
      user_id: user.id,
      scope: scopes.join(" "),
      scopes,
      expires_at: new Date(Date.now() + 1000 * 60 * 60).toISOString()
    }).then(() => {}).catch(() => {});

    return res.json(response);
  } catch (error) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: error.message
    });
  }
});

app.get("/oauth/userinfo", async (req, res) => {
  try {
    const authorization = String(req.headers.authorization || "");
    const token = authorization.startsWith("Bearer ")
      ? authorization.slice("Bearer ".length)
      : "";
    const claims = verifyJwt(token);
    const scopes = String(claims.scope || "").split(" ");

    const { data } = await db.auth.admin.getUserById(claims.sub);
    const user = data?.user;

    if (!user) {
      return res.status(401).json({ error: "invalid_token" });
    }

    const profile = publicUser(user);

    return res.json({
      sub: user.id,
      name: scopes.includes("profile") ? profile.displayName : undefined,
      email: scopes.includes("email") ? user.email : undefined,
      picture: scopes.includes("profile") ? profile.avatarUrl : undefined
    });
  } catch (error) {
    return res.status(401).json({ error: "invalid_token" });
  }
});

/* =========================
   DEVELOPER OAUTH APPS
========================= */

function publicOAuthClient(row, includeSecret = null) {
  return {
    id: row.id,
    clientId: row.client_id,
    clientSecret: includeSecret,
    name: row.name,
    redirectUris: row.redirect_uris || [],
    allowedScopes: row.allowed_scopes || DEFAULT_OAUTH_SCOPES,
    isActive: row.is_active !== false,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

app.get("/api/developer/oauth/apps", requireAuth, async (req, res) => {
  const { data, error } = await db
    .from("oauth_clients")
    .select("id, client_id, name, redirect_uris, allowed_scopes, is_active, created_at, updated_at")
    .eq("created_by", req.user.id)
    .order("created_at", { ascending: false });

  if (error) {
    return res.status(400).json({
      ok: false,
      error: "developer_apps_load_failed",
      message: error.message
    });
  }

  return res.json({
    ok: true,
    apps: (data || []).map((row) => publicOAuthClient(row))
  });
});

app.post("/api/developer/oauth/apps", requireAuth, requireMfaIfEnabled, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const redirectUris = normalizeRedirectUris(
      req.body.redirectUris || req.body.redirect_uris || req.body.callbackUrl || req.body.redirectUri
    );
    const allowedScopes = normalizeScopes(req.body.allowedScopes || req.body.allowed_scopes || req.body.scopes);

    if (name.length < 2 || name.length > 80) {
      return res.status(400).json({
        ok: false,
        error: "invalid_app_name"
      });
    }

    if (!redirectUris.length) {
      return res.status(400).json({
        ok: false,
        error: "missing_redirect_uri"
      });
    }

    if (!allowedScopes.length) {
      return res.status(400).json({
        ok: false,
        error: "invalid_scopes"
      });
    }

    const clientId = generateOpaqueToken("lk_client", 18);
    const clientSecret = generateOpaqueToken("lk_secret", 36);

    const { data, error } = await db
      .from("oauth_clients")
      .insert({
        client_id: clientId,
        client_secret_hash: hashValue(clientSecret),
        name,
        redirect_uris: redirectUris,
        allowed_scopes: allowedScopes,
        is_public: false,
        is_active: true,
        created_by: req.user.id,
        updated_at: new Date().toISOString()
      })
      .select("id, client_id, name, redirect_uris, allowed_scopes, is_active, created_at, updated_at")
      .single();

    if (error) {
      return res.status(400).json({
        ok: false,
        error: "developer_app_create_failed",
        message: error.message,
        hint: "Run supabase-oauth-developer-apps.sql before creating apps."
      });
    }

    await logEvent(req, {
      action: "developer.oauth_app_created",
      target: "oauth.client",
      metadata: {
        clientIdHash: hashValue(clientId),
        redirectUriCount: redirectUris.length,
        scopes: allowedScopes
      }
    });

    // The client secret is returned once. Only its hash is stored in Supabase.
    return res.status(201).json({
      ok: true,
      app: publicOAuthClient(data, clientSecret)
    });
  } catch (error) {
    return res.status(400).json({
      ok: false,
      error: error.message || "invalid_developer_app_payload"
    });
  }
});

app.delete("/api/developer/oauth/apps/:clientId", requireAuth, requireMfaIfEnabled, async (req, res) => {
  const clientId = String(req.params.clientId || "");

  const { data, error } = await db
    .from("oauth_clients")
    .update({
      is_active: false,
      updated_at: new Date().toISOString()
    })
    .eq("client_id", clientId)
    .eq("created_by", req.user.id)
    .select("client_id")
    .single();

  if (error || !data) {
    return res.status(404).json({
      ok: false,
      error: "developer_app_not_found"
    });
  }

  await logEvent(req, {
    action: "developer.oauth_app_revoked",
    target: "oauth.client",
    metadata: {
      clientIdHash: hashValue(clientId)
    }
  });

  return res.json({ ok: true });
});

/* =========================
   SUPABASE OAUTH SERVER CONSENT
========================= */

function getScopeLabel(scope) {
  const labels = {
    openid: "Identificar sua conta Lukintosh",
    profile: "Ver seu perfil básico",
    email: "Ver seu e-mail"
  };

  return labels[scope] || scope;
}

app.get("/oauth/consent", async (req, res) => {
  try {
    const authorizationId = String(req.query.authorization_id || "");

    if (!authorizationId) {
      return res.status(400).send("Missing authorization_id");
    }

    const auth = await refreshSessionIfNeeded(req, res);

    if (!auth) {
      const returnTo = getApiUrl(
        `/oauth/consent?authorization_id=${encodeURIComponent(authorizationId)}`
      );

      return res.redirect(
        getFrontendUrl(`?returnTo=${encodeURIComponent(returnTo)}`)
      );
    }

    const authedSupabase = createAuthedSupabaseClient(auth.accessToken);

    const { data: authDetails, error } =
      await authedSupabase.auth.oauth.getAuthorizationDetails(authorizationId);

    if (error || !authDetails) {
      console.error("OAuth getAuthorizationDetails error:", error);

      return res.status(400).send(
        escapeHtml(error?.message || "Invalid OAuth authorization request")
      );
    }

    // Se o usuário já tinha consentido antes, o Supabase pode mandar redirecionar direto.
    if (!("authorization_id" in authDetails)) {
      return res.redirect(authDetails.redirect_url);
    }

    const clientName =
      authDetails.client?.name ||
      authDetails.client?.client_name ||
      "Aplicativo externo";

    const redirectUri = authDetails.redirect_uri || "Redirect URI indisponível";

    const scopes = String(authDetails.scope || "")
      .split(" ")
      .map((scope) => scope.trim())
      .filter(Boolean);

    const scopeItems = scopes.length
      ? scopes
          .map((scope) => `<li>${escapeHtml(getScopeLabel(scope))}</li>`)
          .join("")
      : "<li>Identificar sua conta Lukintosh</li>";

    return res.send(`
      <!doctype html>
      <html lang="pt-BR">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>Entrar com Lukintosh</title>

          <style>
            * {
              box-sizing: border-box;
            }

            body {
              margin: 0;
              min-height: 100vh;
              display: grid;
              place-items: center;
              background:
                radial-gradient(circle at top, rgba(120, 145, 255, .22), transparent 34%),
                #050507;
              color: #f5f5f7;
              font-family: Inter, Arial, sans-serif;
              padding: 22px;
            }

            .card {
              width: min(480px, 100%);
              padding: 30px;
              border-radius: 30px;
              background: rgba(255,255,255,.075);
              border: 1px solid rgba(255,255,255,.14);
              box-shadow: 0 30px 90px rgba(0,0,0,.48);
              backdrop-filter: blur(18px);
            }

            .logo {
              width: 44px;
              height: 44px;
              border-radius: 15px;
              background: linear-gradient(145deg,#fff,#8ab4ff 45%,#b49cff);
              margin-bottom: 18px;
            }

            h1 {
              margin: 0 0 10px;
              font-size: 29px;
              line-height: 1;
              letter-spacing: -1.3px;
            }

            p {
              color: #b9b9c4;
              line-height: 1.55;
              margin: 10px 0;
            }

            .app-box {
              margin: 20px 0;
              padding: 16px;
              border-radius: 20px;
              background: rgba(255,255,255,.06);
              border: 1px solid rgba(255,255,255,.1);
            }

            .app-name {
              font-size: 18px;
              font-weight: 850;
              color: #ffffff;
            }

            .uri {
              margin-top: 8px;
              color: #8e8e99;
              font-size: 12px;
              overflow-wrap: anywhere;
            }

            ul {
              margin: 12px 0 20px;
              padding-left: 20px;
              color: #e5e8ff;
              line-height: 1.7;
            }

            button {
              width: 100%;
              border: 0;
              border-radius: 999px;
              padding: 14px 18px;
              margin-top: 10px;
              font-weight: 850;
              cursor: pointer;
              font-size: 15px;
            }

            .approve {
              background: #f5f5f7;
              color: #050507;
            }

            .deny {
              background: rgba(255,255,255,.12);
              color: #f5f5f7;
            }

            .footer {
              margin-top: 18px;
              color: #767681;
              font-size: 12px;
            }
          </style>
        </head>

        <body>
          <main class="card">
            <div class="logo"></div>

            <h1>Entrar com Lukintosh</h1>

            <p>
              Revise a solicitação antes de continuar.
            </p>

            <div class="app-box">
              <div class="app-name">${escapeHtml(clientName)}</div>
              <div class="uri">${escapeHtml(redirectUri)}</div>
            </div>

            <p>Este app quer acessar:</p>

            <ul>
              ${scopeItems}
            </ul>

            <form method="post" action="/oauth/consent/decision">
              <input type="hidden" name="authorization_id" value="${escapeHtml(authorizationId)}" />
              <input type="hidden" name="decision" value="approve" />
              <button class="approve" type="submit">Continuar com Lukintosh</button>
            </form>

            <form method="post" action="/oauth/consent/decision">
              <input type="hidden" name="authorization_id" value="${escapeHtml(authorizationId)}" />
              <input type="hidden" name="decision" value="deny" />
              <button class="deny" type="submit">Cancelar</button>
            </form>

            <p class="footer">
              Lukintosh Accounts protege sua identidade e nunca compartilha sua senha com este app.
            </p>
          </main>
        </body>
      </html>
    `);
  } catch (error) {
    console.error("OAuth consent page error:", error);

    return res.status(500).send("OAuth consent failed");
  }
});

app.post("/oauth/consent/decision", requireAuth, async (req, res) => {
  try {
    const authorizationId = String(req.body.authorization_id || "");
    const decision = String(req.body.decision || "");

    if (!authorizationId) {
      return res.status(400).send("Missing authorization_id");
    }

    const authedSupabase = createAuthedSupabaseClient(req.accessToken);

    let result;

    if (decision === "approve") {
      result = await authedSupabase.auth.oauth.approveAuthorization(
        authorizationId
      );
    } else if (decision === "deny") {
      result = await authedSupabase.auth.oauth.denyAuthorization(
        authorizationId
      );
    } else {
      return res.status(400).send("Invalid OAuth decision");
    }

    const { data, error } = result;

    if (error || !data?.redirect_url) {
      console.error("OAuth decision error:", error);

      return res.status(400).send(
        escapeHtml(error?.message || "OAuth decision failed")
      );
    }

    await logEvent(req, {
      action:
        decision === "approve"
          ? "oauth.authorization_approved"
          : "oauth.authorization_denied",
      target: "oauth.authorization",
      metadata: {
        authorizationId
      }
    });

    return res.redirect(data.redirect_url);
  } catch (error) {
    console.error("OAuth consent decision fatal error:", error);

    return res.status(500).send("OAuth decision failed");
  }
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
  console.log(`Cookie mode: global-lukintosh-cookie`);
  console.log(`Email enabled: ${Boolean(resend)}`);
});
