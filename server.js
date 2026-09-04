const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const path = require("path");
const forge = require("node-forge");
const { execFileSync } = require("child_process");
const db = require("./database");

// DEVICE TOKEN V3
function ensureDeviceTokenColumns() {
    const statements = [
        "ALTER TABLE keys ADD COLUMN device_token_hash TEXT",
        "ALTER TABLE device_enrollments ADD COLUMN device_token TEXT"
    ];

    for (const sql of statements) {
        try {
            db.prepare(sql).run();
        } catch (error) {
            if (
                !String(error?.message || "")
                    .toLowerCase()
                    .includes("duplicate column")
            ) {
                throw error;
            }
        }
    }
}

ensureDeviceTokenColumns();


/* =========================================================
   REVENDEDORES / SALDO / PIX
========================================================= */

function ensureResellerTables() {
    db.exec(`
        CREATE TABLE IF NOT EXISTS resellers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            balance_cents INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login_at TEXT
        );

        CREATE TABLE IF NOT EXISTS reseller_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT UNIQUE NOT NULL,
            reseller_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (reseller_id)
                REFERENCES resellers(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reseller_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reseller_id INTEGER NOT NULL,
            key_id INTEGER NOT NULL,
            price_cents INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (reseller_id)
                REFERENCES resellers(id)
                ON DELETE CASCADE,
            FOREIGN KEY (key_id)
                REFERENCES keys(id)
                ON DELETE CASCADE,
            UNIQUE(reseller_id, key_id)
        );

        CREATE TABLE IF NOT EXISTS reseller_deposits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reseller_id INTEGER NOT NULL,
            payment_id TEXT UNIQUE,
            amount_cents INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            credited INTEGER NOT NULL DEFAULT 0,
            idempotency_key TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            approved_at TEXT,
            FOREIGN KEY (reseller_id)
                REFERENCES resellers(id)
                ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_reseller_sessions_hash
            ON reseller_sessions(token_hash);

        CREATE INDEX IF NOT EXISTS idx_reseller_keys_reseller
            ON reseller_keys(reseller_id);

        CREATE INDEX IF NOT EXISTS idx_reseller_deposits_payment
            ON reseller_deposits(payment_id);
    `);
}

ensureResellerTables();

const RESELLER_SESSION_HOURS = 168;
const RESELLER_MIN_DEPOSIT_CENTS = 2500;

const RESELLER_PLANS = {
    "1d": {
        days: 1,
        priceCents: 511
    },
    "7d": {
        days: 7,
        priceCents: 1429
    },
    "30d": {
        days: 30,
        priceCents: 2590
    }
};

function resellerPublic(row) {
    return {
        id: row.id,
        username: row.username,
        email: row.email,
        enabled: Boolean(row.enabled),
        balance: Number(row.balance_cents || 0) / 100,
        created_at: row.created_at,
        last_login_at: row.last_login_at
    };
}

function createResellerSession(resellerId) {
    const token =
        crypto.randomBytes(32).toString("hex");

    const expiresAt =
        new Date(
            Date.now() +
            RESELLER_SESSION_HOURS *
            60 *
            60 *
            1000
        ).toISOString();

    db.prepare(`
        INSERT INTO reseller_sessions (
            token_hash,
            reseller_id,
            expires_at
        )
        VALUES (?, ?, ?)
    `).run(
        hashToken(token),
        resellerId,
        expiresAt
    );

    return {
        token,
        expiresAt
    };
}

function resellerAuthRequired(req, res, next) {
    try {
        const token = getBearerToken(req);

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Nao autenticado"
            });
        }

        const session = db.prepare(`
            SELECT
                reseller_sessions.id AS session_id,
                reseller_sessions.expires_at AS session_expires_at,
                resellers.*
            FROM reseller_sessions
            JOIN resellers
                ON resellers.id =
                   reseller_sessions.reseller_id
            WHERE reseller_sessions.token_hash = ?
        `).get(
            hashToken(token)
        );

        if (!session) {
            return res.status(401).json({
                success: false,
                message: "Sessao invalida"
            });
        }

        if (
            new Date(
                session.session_expires_at
            ).getTime() <= Date.now()
        ) {
            db.prepare(`
                DELETE FROM reseller_sessions
                WHERE id = ?
            `).run(
                session.session_id
            );

            return res.status(401).json({
                success: false,
                message: "Sessao expirada"
            });
        }

        if (!session.enabled) {
            return res.status(403).json({
                success: false,
                message: "Conta de revendedor desativada"
            });
        }

        req.reseller = session;
        req.resellerToken = token;

        return next();

    } catch (error) {
        return next(error);
    }
}

const MERCADO_PAGO_ACCESS_TOKEN =
    "APP_USR-3633110140034859-050122-61bd6bb16839481b26f72ed5863250d5-3373691578";

function mercadoPagoAccessToken() {
    return String(
        MERCADO_PAGO_ACCESS_TOKEN ||
        ""
    ).trim();
}

async function mercadoPagoRequest(
    endpoint,
    options = {}
) {
    const accessToken =
        mercadoPagoAccessToken();

    if (!accessToken) {
        const error =
            new Error(
                "Access Token do Mercado Pago nao configurado no server.js"
            );

        error.code =
            "MERCADO_PAGO_NOT_CONFIGURED";

        throw error;
    }

    const headers = {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...(options.headers || {})
    };

    headers.Authorization =
        `Bearer ${accessToken}`;

    const response =
        await fetch(
            "https://api.mercadopago.com" +
            endpoint,
            {
                method:
                    options.method ||
                    "GET",
                headers,
                body:
                    options.body
            }
        );

    const raw =
        await response.text();

    let data = {};

    try {
        data =
            raw
                ? JSON.parse(raw)
                : {};
    } catch {
        data = {
            message:
                raw ||
                "Resposta invalida do Mercado Pago"
        };
    }

    if (!response.ok) {
        const error =
            new Error(
                data.message ||
                data.error ||
                "Erro no Mercado Pago"
            );

        error.status =
            response.status;

        error.details =
            data;

        throw error;
    }

    return data;
}

function creditApprovedDeposit(
    paymentId,
    paymentStatus
) {
    const deposit =
        db.prepare(`
            SELECT *
            FROM reseller_deposits
            WHERE payment_id = ?
        `).get(
            String(paymentId)
        );

    if (!deposit) {
        return null;
    }

    const normalizedStatus =
        String(
            paymentStatus || ""
        ).toLowerCase();

    if (
        normalizedStatus !==
        "approved"
    ) {
        db.prepare(`
            UPDATE reseller_deposits
            SET status = ?
            WHERE id = ?
        `).run(
            normalizedStatus ||
            "pending",
            deposit.id
        );

        return db.prepare(`
            SELECT *
            FROM resellers
            WHERE id = ?
        `).get(
            deposit.reseller_id
        );
    }

    const applyCredit =
        db.transaction(() => {
            const fresh =
                db.prepare(`
                    SELECT *
                    FROM reseller_deposits
                    WHERE id = ?
                `).get(
                    deposit.id
                );

            if (!fresh) {
                return null;
            }

            if (!fresh.credited) {
                db.prepare(`
                    UPDATE resellers
                    SET balance_cents =
                        balance_cents + ?
                    WHERE id = ?
                `).run(
                    fresh.amount_cents,
                    fresh.reseller_id
                );

                db.prepare(`
                    UPDATE reseller_deposits
                    SET
                        status = 'approved',
                        credited = 1,
                        approved_at = ?
                    WHERE id = ?
                `).run(
                    nowISO(),
                    fresh.id
                );
            } else {
                db.prepare(`
                    UPDATE reseller_deposits
                    SET status = 'approved'
                    WHERE id = ?
                `).run(
                    fresh.id
                );
            }

            return db.prepare(`
                SELECT *
                FROM resellers
                WHERE id = ?
            `).get(
                fresh.reseller_id
            );
        });

    return applyCredit();
}

async function syncMercadoPagoPayment(
    paymentId
) {
    const payment =
        await mercadoPagoRequest(
            "/v1/payments/" +
            encodeURIComponent(
                String(paymentId)
            ),
            {
                method: "GET"
            }
        );

    const reseller =
        creditApprovedDeposit(
            payment.id,
            payment.status
        );

    return {
        payment,
        reseller
    };
}


const app = express();

const PORT = Number(process.env.PORT) || 80;
const HOST = "0.0.0.0";
const PUBLIC_URL =
    process.env.PUBLIC_URL ||
    "https://externalconfig.shardweb.app";

const MASTER_OWNER = "nextaway";
const SESSION_HOURS = 24;
const MAX_KEYS_PER_REQUEST = 100;
const DEVICE_ENROLLMENT_MINUTES = 10;
const DEVICE_FETCHER_CACHE_LIMIT = 500;

app.use(cors({
    origin: true,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "64kb" }));
app.use(express.static(path.join(__dirname, "site")));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "site", "index.html"));
});

app.get("/health", (req, res) => {
    res.json({
        ok: true,
        message: "API funcionando",
        url: PUBLIC_URL
    });
});

/* =========================================================
   UTILIDADES
========================================================= */

function nowISO() {
    return new Date().toISOString();
}

function normalizeUsername(value) {
    return String(value || "").trim().toLowerCase();
}

function normalizeUDID(value) {
    return String(value || "")
        .trim()
        .replace(/\s+/g, "")
        .toUpperCase();
}

function validUDID(value) {
    return /^[A-Z0-9-]{8,128}$/.test(value);
}

function sanitizePrefix(value) {
    const prefix = String(value || "EXTERNAL")
        .trim()
        .toUpperCase()
        .replace(/[^A-Z0-9_-]/g, "");

    return prefix || "EXTERNAL";
}

function randomCode(length = 5) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let result = "";

    for (let i = 0; i < length; i++) {
        result += chars[crypto.randomInt(0, chars.length)];
    }

    return result;
}

function generateKeyValue(prefix = "EXTERNAL") {
    return `${sanitizePrefix(prefix)}-IOS-${randomCode(5)}`;
}

function calculateExpiration(days, from = Date.now()) {
    return new Date(
        from + Number(days) * 24 * 60 * 60 * 1000
    ).toISOString();
}

function getDaysFromKey(keyData) {
    const value = String(keyData.last_reset_at || "");

    if (value.startsWith("PLAN:")) {
        const days = Number(value.slice(5));
        return Number.isFinite(days) ? days : null;
    }

    return null;
}

function getKey(value) {
    return db.prepare(`
        SELECT *
        FROM keys
        WHERE key = ?
    `).get(String(value || "").trim());
}

function isKeyAdminUser(user) {
    if (!user) return false;

    return (
        String(user.role || "").toLowerCase() === "owner" ||
        String(user.username || "").toLowerCase() === "nextaway"
    );
}

function getAccessibleKey(value, user) {
    const normalizedKey = String(value || "").trim();

    if (isKeyAdminUser(user)) {
        return db.prepare(`
            SELECT *
            FROM keys
            WHERE key = ?
        `).get(normalizedKey);
    }

    return db.prepare(`
        SELECT *
        FROM keys
        WHERE key = ?
          AND created_by_user_id = ?
    `).get(
        normalizedKey,
        Number(user.id)
    );
}

function checkKeyExpiration(keyData) {
    if (
        keyData.status === "active" &&
        keyData.expires_at &&
        new Date(keyData.expires_at).getTime() <= Date.now()
    ) {
        db.prepare(`
            UPDATE keys
            SET status = 'expired'
            WHERE id = ?
        `).run(keyData.id);

        return "expired";
    }

    return keyData.status;
}


function normalizeDeviceToken(value) {
    return String(value || "").trim();
}

function deviceTokenMatches(keyData, token) {
    const supplied =
        normalizeDeviceToken(token);

    if (
        !keyData ||
        !keyData.device_token_hash ||
        !supplied
    ) {
        return false;
    }

    const actual =
        Buffer.from(
            hashToken(supplied),
            "hex"
        );

    const expected =
        Buffer.from(
            String(keyData.device_token_hash),
            "hex"
        );

    return (
        actual.length === expected.length &&
        crypto.timingSafeEqual(
            actual,
            expected
        )
    );
}

function issueDeviceTokenForEnrollment(
    keyData,
    enrollmentId
) {
    const token =
        crypto.randomBytes(32)
            .toString("hex");

    db.prepare(`
        UPDATE keys
        SET device_token_hash = ?
        WHERE id = ?
    `).run(
        hashToken(token),
        keyData.id
    );

    db.prepare(`
        UPDATE device_enrollments
        SET device_token = ?
        WHERE id = ?
    `).run(
        token,
        enrollmentId
    );

    return token;
}

function createDeviceEnrollmentSession(keyData) {
    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = hashToken(token);

    const expiresAt = new Date(
        Date.now() +
        DEVICE_ENROLLMENT_MINUTES * 60 * 1000
    ).toISOString();

    db.prepare(`
        DELETE FROM device_enrollments
        WHERE key_id = ?
          AND status = 'pending'
    `).run(keyData.id);

    db.prepare(`
        INSERT INTO device_enrollments (
            token_hash,
            key_id,
            status,
            expires_at
        )
        VALUES (?, ?, 'pending', ?)
    `).run(
        tokenHash,
        keyData.id,
        expiresAt
    );

    return {
        token,
        expiresAt
    };
}

function getDeviceEnrollment(token) {
    return db.prepare(`
        SELECT
            device_enrollments.*,
            keys.key,
            keys.status AS key_status,
            keys.expires_at AS key_expires_at,
            keys.last_reset_at,
            keys.device_udid
        FROM device_enrollments
        INNER JOIN keys
            ON keys.id = device_enrollments.key_id
        WHERE device_enrollments.token_hash = ?
    `).get(
        hashToken(token)
    );
}

function enrollmentIsExpired(enrollment) {
    return (
        !enrollment ||
        new Date(enrollment.expires_at).getTime() <= Date.now()
    );
}

function deviceValue(device, ...names) {
    if (!device || typeof device !== "object") {
        return "";
    }

    for (const name of names) {
        const value = device[name];

        if (
            value !== undefined &&
            value !== null &&
            String(value).trim()
        ) {
            return String(value).trim();
        }
    }

    return "";
}

function activateKeyAfterDeviceEnrollment(keyData, udid) {
    const fresh = getKey(keyData.key);

    if (!fresh) {
        throw new Error("Key não encontrada");
    }

    const status = checkKeyExpiration(fresh);

    if (status === "expired") {
        throw new Error("Key expirada");
    }

    if (status === "paused") {
        throw new Error("Key pausada");
    }

    if (fresh.device_udid) {
        if (
            normalizeUDID(fresh.device_udid) !==
            normalizeUDID(udid)
        ) {
            const error = new Error(
                "Key usada em outro dispositivo."
            );

            error.code = "DEVICE_MISMATCH";
            throw error;
        }
    } else {
        const boundAt = nowISO();

        const update = db.prepare(`
            UPDATE keys
            SET
                device_udid = ?,
                device_bound_at = ?,
                device_reset_at = NULL
            WHERE id = ?
              AND device_udid IS NULL
        `).run(
            normalizeUDID(udid),
            boundAt,
            fresh.id
        );

        if (update.changes !== 1) {
            const latest = getKey(fresh.key);

            if (
                latest &&
                latest.device_udid &&
                normalizeUDID(latest.device_udid) !==
                    normalizeUDID(udid)
            ) {
                const error = new Error(
                    "Key usada em outro dispositivo."
                );

                error.code = "DEVICE_MISMATCH";
                throw error;
            }
        }
    }

    if (status === "unused") {
        const days = getDaysFromKey(fresh);

        if (
            !Number.isInteger(days) ||
            days <= 0
        ) {
            throw new Error(
                "Plano da key inválido"
            );
        }

        const activatedAt = nowISO();
        const expiresAt =
            calculateExpiration(days);

        db.prepare(`
            UPDATE keys
            SET
                status = 'active',
                activated_at = ?,
                expires_at = ?,
                paused_at = NULL,
                remaining_ms = NULL
            WHERE id = ?
        `).run(
            activatedAt,
            expiresAt,
            fresh.id
        );
    }

    return getKey(fresh.key);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
    const hash = crypto
        .scryptSync(String(password), salt, 64)
        .toString("hex");

    return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
    try {
        const actual = crypto.scryptSync(String(password), salt, 64);
        const expected = Buffer.from(expectedHash, "hex");

        return (
            actual.length === expected.length &&
            crypto.timingSafeEqual(actual, expected)
        );
    } catch {
        return false;
    }
}

function hashToken(token) {
    return crypto
        .createHash("sha256")
        .update(String(token))
        .digest("hex");
}

function createSession(userId) {
    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = hashToken(token);
    const expiresAt = new Date(
        Date.now() + SESSION_HOURS * 60 * 60 * 1000
    ).toISOString();

    db.prepare(`
        INSERT INTO sessions (
            token_hash,
            user_id,
            expires_at
        )
        VALUES (?, ?, ?)
    `).run(tokenHash, userId, expiresAt);

    return { token, expiresAt };
}

function getBearerToken(req) {
    const auth = String(req.headers.authorization || "");
    return auth.startsWith("Bearer ")
        ? auth.slice(7).trim()
        : null;
}

function hasValidPanelSession(req) {
    try {
        const token = getBearerToken(req);

        if (!token) {
            return false;
        }

        const session = db.prepare(`
            SELECT
                sessions.expires_at AS session_expires_at,
                users.enabled,
                users.account_status
            FROM sessions
            JOIN users
                ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
        `).get(hashToken(token));

        if (!session) {
            return false;
        }

        if (
            new Date(
                session.session_expires_at
            ).getTime() <= Date.now()
        ) {
            return false;
        }

        if (!session.enabled) {
            return false;
        }

        if (
            String(
                session.account_status || ""
            ).toLowerCase() === "expired"
        ) {
            return false;
        }

        return true;

    } catch (error) {
        console.error(
            "Erro validando sessão opcional do painel:",
            error
        );

        return false;
    }
}

function logAction(userId, action, targetType = null, targetId = null) {
    try {
        db.logAction(userId, action, targetType, targetId);
    } catch (error) {
        console.error("Falha na auditoria:", error.message);
    }
}

function parseAccountPlan(body) {
    const plan = String(body.account_plan || body.plan || "lifetime")
        .trim()
        .toLowerCase();

    const fixed = {
        "1d": 1,
        "7d": 7,
        "30d": 30
    };

    if (Object.prototype.hasOwnProperty.call(fixed, plan)) {
        return {
            plan,
            durationDays: fixed[plan]
        };
    }

    if (plan === "lifetime") {
        return {
            plan: "lifetime",
            durationDays: null
        };
    }

    if (plan === "custom") {
        const days = Number(
            body.duration_days ??
            body.days
        );

        if (
            !Number.isInteger(days) ||
            days <= 0 ||
            days > 36500
        ) {
            throw new Error("Duração personalizada inválida");
        }

        return {
            plan: "custom",
            durationDays: days
        };
    }

    throw new Error("Plano da conta inválido");
}

function parseKeyLimit(value) {
    if (
        value === null ||
        value === undefined ||
        value === "" ||
        String(value).toLowerCase() === "unlimited"
    ) {
        return null;
    }

    const limit = Number(value);

    if (
        !Number.isInteger(limit) ||
        limit < 0 ||
        limit > 10000000
    ) {
        throw new Error("Limite de keys inválido");
    }

    return limit;
}

function refreshAccountStatus(user) {
    if (!user) return null;

    if (normalizeUsername(user.username) === MASTER_OWNER) {
        if (
            user.role !== "owner" ||
            !user.enabled ||
            user.account_status !== "active" ||
            user.account_plan !== "lifetime" ||
            user.expires_at !== null ||
            user.key_limit !== null
        ) {
            db.prepare(`
                UPDATE users
                SET
                    role = 'owner',
                    enabled = 1,
                    account_status = 'active',
                    account_plan = 'lifetime',
                    duration_days = NULL,
                    activated_at = COALESCE(activated_at, created_at),
                    expires_at = NULL,
                    key_limit = NULL
                WHERE id = ?
            `).run(user.id);

            return db.getUserById(user.id);
        }

        return user;
    }

    if (
        user.account_status === "active" &&
        user.account_plan !== "lifetime" &&
        user.expires_at &&
        new Date(user.expires_at).getTime() <= Date.now()
    ) {
        db.prepare(`
            UPDATE users
            SET account_status = 'expired'
            WHERE id = ?
        `).run(user.id);

        db.prepare(`
            DELETE FROM sessions
            WHERE user_id = ?
        `).run(user.id);

        return db.getUserById(user.id);
    }

    return user;
}

function activateAccountOnFirstLogin(user) {
    user = refreshAccountStatus(user);

    if (!user) return null;

    if (
        normalizeUsername(user.username) === MASTER_OWNER ||
        user.account_status !== "unused"
    ) {
        return user;
    }

    const activatedAt = nowISO();
    const expiresAt =
        user.account_plan === "lifetime"
            ? null
            : calculateExpiration(user.duration_days);

    db.prepare(`
        UPDATE users
        SET
            account_status = 'active',
            activated_at = ?,
            expires_at = ?
        WHERE id = ?
    `).run(
        activatedAt,
        expiresAt,
        user.id
    );

    return db.getUserById(user.id);
}

function accountPublic(user) {
    user = refreshAccountStatus(user);

    const limit =
        user.key_limit === null ||
        user.key_limit === undefined
            ? null
            : Number(user.key_limit);

    const generated = Number(user.keys_generated || 0);

    return {
        id: user.id,
        username: user.username,
        role: user.role,
        enabled: Boolean(user.enabled),

        account_status: user.account_status,
        account_plan: user.account_plan,
        duration_days: user.duration_days,

        activated_at: user.activated_at,
        expires_at: user.expires_at,

        key_limit: limit,
        keys_generated: generated,
        keys_remaining:
            limit === null
                ? null
                : Math.max(0, limit - generated),
        unlimited_keys: limit === null,

        created_at: user.created_at,
        created_by: user.created_by,
        last_login_at: user.last_login_at,

        master_owner:
            normalizeUsername(user.username) === MASTER_OWNER
    };
}

/* =========================================================
   MASTER OWNER
========================================================= */

function ensureMasterOwner() {
    const password = String(
        process.env.NEXTAWAY_PASSWORD || ""
    );

    let owner =
        db.getUserByUsername(
            MASTER_OWNER
        );

    if (owner) {
        refreshAccountStatus(owner);

        /*
         * Mantém a senha do master owner sincronizada
         * com NEXTAWAY_PASSWORD em todo startup/deploy.
         * Assim o painel não fica preso a um hash antigo
         * caso o banco seja recriado/restaurado.
         */
        if (password.length >= 8) {
            const { salt, hash } =
                hashPassword(password);

            db.prepare(`
                UPDATE users
                SET
                    password_hash = ?,
                    password_salt = ?,
                    role = 'owner',
                    enabled = 1,
                    account_status = 'active',
                    account_plan = 'lifetime',
                    duration_days = NULL,
                    expires_at = NULL,
                    key_limit = NULL
                WHERE id = ?
            `).run(
                hash,
                salt,
                owner.id
            );

            console.log(
                'Senha do master owner "nextaway" sincronizada com NEXTAWAY_PASSWORD.'
            );
        } else {
            console.warn(
                "ATENÇÃO: NEXTAWAY_PASSWORD precisa ter pelo menos 8 caracteres."
            );
        }

        return;
    }

    if (password.length < 8) {
        console.warn(
            "ATENÇÃO: defina NEXTAWAY_PASSWORD com pelo menos 8 caracteres."
        );
        return;
    }

    const { salt, hash } =
        hashPassword(password);

    db.prepare(`
        INSERT INTO users (
            username,
            password_hash,
            password_salt,
            role,
            enabled,
            account_status,
            account_plan,
            duration_days,
            activated_at,
            expires_at,
            key_limit,
            keys_generated,
            created_by
        )
        VALUES (
            ?, ?, ?,
            'owner',
            1,
            'active',
            'lifetime',
            NULL,
            ?,
            NULL,
            NULL,
            0,
            'system'
        )
    `).run(
        MASTER_OWNER,
        hash,
        salt,
        nowISO()
    );

    console.log(
        'Conta master owner "nextaway" criada.'
    );
}
ensureMasterOwner();

/* =========================================================
   AUTH
========================================================= */

function authRequired(req, res, next) {
    try {
        const token = getBearerToken(req);

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Não autenticado"
            });
        }

        const session = db.prepare(`
            SELECT
                sessions.id AS session_id,
                sessions.expires_at AS session_expires_at,
                users.*
            FROM sessions
            JOIN users
                ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
        `).get(hashToken(token));

        if (!session) {
            return res.status(401).json({
                success: false,
                message: "Sessão inválida"
            });
        }

        if (
            new Date(session.session_expires_at).getTime() <= Date.now()
        ) {
            db.prepare(`
                DELETE FROM sessions
                WHERE id = ?
            `).run(session.session_id);

            return res.status(401).json({
                success: false,
                message: "Sessão expirada"
            });
        }

        let user = refreshAccountStatus(session);

        if (!user.enabled) {
            db.prepare(`
                DELETE FROM sessions
                WHERE user_id = ?
            `).run(user.id);

            return res.status(401).json({
                success: false,
                message: "Conta desativada"
            });
        }

        if (user.account_status === "expired") {
            db.prepare(`
                DELETE FROM sessions
                WHERE user_id = ?
            `).run(user.id);

            return res.status(401).json({
                success: false,
                code: "ACCOUNT_EXPIRED",
                message: "Conta expirada"
            });
        }

        req.user = user;
        req.sessionToken = token;
        return next();

    } catch (error) {
        return next(error);
    }
}

function ownerRequired(req, res, next) {
    if (!req.user || req.user.role !== "owner") {
        return res.status(403).json({
            success: false,
            message: "Acesso permitido somente ao owner"
        });
    }

    return next();
}

function masterOwnerRequired(req, res, next) {
    if (
        !req.user ||
        normalizeUsername(req.user.username) !== MASTER_OWNER
    ) {
        return res.status(403).json({
            success: false,
            message: "Acesso permitido somente ao master owner"
        });
    }

    return next();
}

app.post("/api/auth/login", (req, res) => {
    try {
        const username =
            normalizeUsername(req.body.username);

        const password =
            String(req.body.password || "");

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: "Usuário e senha são obrigatórios"
            });
        }

        let user = db.getUserByUsername(username);

        if (
            !user ||
            !user.enabled ||
            !verifyPassword(
                password,
                user.password_salt,
                user.password_hash
            )
        ) {
            return res.status(401).json({
                success: false,
                message: "Usuário ou senha inválidos"
            });
        }

        user = refreshAccountStatus(user);

        if (user.account_status === "expired") {
            return res.status(403).json({
                success: false,
                code: "ACCOUNT_EXPIRED",
                message: "Esta conta expirou"
            });
        }

        user = activateAccountOnFirstLogin(user);

        const loginAt = nowISO();

        db.prepare(`
            UPDATE users
            SET last_login_at = ?
            WHERE id = ?
        `).run(loginAt, user.id);

        user = db.getUserById(user.id);

        const session = createSession(user.id);

        logAction(
            user.id,
            "login",
            "user",
            String(user.id)
        );

        return res.json({
            success: true,
            token: session.token,
            expires_at: session.expiresAt,
            user: accountPublic(user)
        });

    } catch (error) {
        console.error("Erro no login:", error);

        return res.status(500).json({
            success: false,
            message: "Erro interno no login"
        });
    }
});

app.get(
    "/api/auth/me",
    authRequired,
    (req, res) => {
        res.json({
            success: true,
            user: accountPublic(req.user)
        });
    }
);

app.post(
    "/api/auth/logout",
    authRequired,
    (req, res) => {
        db.prepare(`
            DELETE FROM sessions
            WHERE token_hash = ?
        `).run(hashToken(req.sessionToken));

        res.json({
            success: true,
            message: "Logout realizado"
        });
    }
);

/* =========================================================
   ADMIN - LISTAR CONTAS
========================================================= */

app.get(
    "/api/admin/users",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const rows = db.prepare(`
                SELECT *
                FROM users
                ORDER BY id DESC
            `).all();

            const users = rows.map(accountPublic);

            res.json({
                success: true,
                total: users.length,
                users
            });

        } catch (error) {
            console.error("Erro ao listar usuários:", error);

            res.status(500).json({
                success: false,
                message: "Erro interno ao listar usuários"
            });
        }
    }
);

/* =========================================================
   ADMIN - CRIAR CONTA
========================================================= */

app.post(
    "/api/admin/users/create",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const username =
                normalizeUsername(req.body.username);

            const password =
                String(req.body.password || "");

            const role =
                String(req.body.role || "user")
                    .trim()
                    .toLowerCase();

            if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
                return res.status(400).json({
                    success: false,
                    message: "Nome de usuário inválido"
                });
            }

            if (password.length < 8) {
                return res.status(400).json({
                    success: false,
                    message: "A senha precisa ter pelo menos 8 caracteres"
                });
            }

            if (!["owner", "user"].includes(role)) {
                return res.status(400).json({
                    success: false,
                    message: "Cargo inválido. Use owner ou user."
                });
            }

            if (username === MASTER_OWNER) {
                return res.status(400).json({
                    success: false,
                    message: "Nome de usuário reservado"
                });
            }

            if (db.getUserByUsername(username)) {
                return res.status(409).json({
                    success: false,
                    message: "Usuário já existe"
                });
            }

            let account;
            let keyLimit;

            try {
                account = parseAccountPlan(req.body);
                keyLimit = parseKeyLimit(req.body.key_limit);
            } catch (error) {
                return res.status(400).json({
                    success: false,
                    message: error.message
                });
            }

            const { salt, hash } =
                hashPassword(password);

            const result = db.prepare(`
                INSERT INTO users (
                    username,
                    password_hash,
                    password_salt,
                    role,
                    enabled,
                    account_status,
                    account_plan,
                    duration_days,
                    activated_at,
                    expires_at,
                    key_limit,
                    keys_generated,
                    created_by
                )
                VALUES (
                    ?, ?, ?, ?, 1,
                    'unused',
                    ?, ?,
                    NULL,
                    NULL,
                    ?,
                    0,
                    ?
                )
            `).run(
                username,
                hash,
                salt,
                role,
                account.plan,
                account.durationDays,
                keyLimit,
                req.user.username
            );

            const created =
                db.getUserById(
                    Number(result.lastInsertRowid)
                );

            logAction(
                req.user.id,
                "create_user",
                "user",
                String(created.id)
            );

            res.json({
                success: true,
                message: "Conta criada com sucesso",
                user: accountPublic(created)
            });

        } catch (error) {
            console.error("Erro ao criar usuário:", error);

            res.status(500).json({
                success: false,
                message: "Erro interno ao criar usuário"
            });
        }
    }
);

/* =========================================================
   ADMIN - EDITAR CONTA
========================================================= */

app.post(
    "/api/admin/users/update",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const id = Number(req.body.id);

            if (!Number.isInteger(id) || id <= 0) {
                return res.status(400).json({
                    success: false,
                    message: "ID de usuário inválido"
                });
            }

            const target = db.getUserById(id);

            if (!target) {
                return res.status(404).json({
                    success: false,
                    message: "Usuário não encontrado"
                });
            }

            if (
                normalizeUsername(target.username) ===
                MASTER_OWNER
            ) {
                return res.status(400).json({
                    success: false,
                    message: "A conta master owner não pode ser alterada"
                });
            }

            const role =
                req.body.role === undefined
                    ? target.role
                    : String(req.body.role)
                        .trim()
                        .toLowerCase();

            if (!["owner", "user"].includes(role)) {
                return res.status(400).json({
                    success: false,
                    message: "Cargo inválido"
                });
            }

            let keyLimit = target.key_limit;

            if (
                Object.prototype.hasOwnProperty.call(
                    req.body,
                    "key_limit"
                )
            ) {
                try {
                    keyLimit =
                        parseKeyLimit(req.body.key_limit);
                } catch (error) {
                    return res.status(400).json({
                        success: false,
                        message: error.message
                    });
                }
            }

            let plan = target.account_plan;
            let durationDays = target.duration_days;

            if (
                req.body.account_plan !== undefined ||
                req.body.plan !== undefined
            ) {
                try {
                    const parsed =
                        parseAccountPlan(req.body);

                    plan = parsed.plan;
                    durationDays =
                        parsed.durationDays;
                } catch (error) {
                    return res.status(400).json({
                        success: false,
                        message: error.message
                    });
                }
            }

            let expiresAt = target.expires_at;

            if (
                target.account_status === "active" &&
                plan !== target.account_plan
            ) {
                expiresAt =
                    plan === "lifetime"
                        ? null
                        : calculateExpiration(
                            durationDays
                        );
            }

            db.prepare(`
                UPDATE users
                SET
                    role = ?,
                    account_plan = ?,
                    duration_days = ?,
                    expires_at = ?,
                    key_limit = ?
                WHERE id = ?
            `).run(
                role,
                plan,
                durationDays,
                expiresAt,
                keyLimit,
                id
            );

            logAction(
                req.user.id,
                "update_user",
                "user",
                String(id)
            );

            res.json({
                success: true,
                message: "Conta atualizada",
                user: accountPublic(
                    db.getUserById(id)
                )
            });

        } catch (error) {
            console.error("Erro ao editar usuário:", error);

            res.status(500).json({
                success: false,
                message: "Erro interno ao editar usuário"
            });
        }
    }
);

/* =========================================================
   ADMIN - ATIVAR / DESATIVAR CONTA
========================================================= */

app.post(
    "/api/admin/users/status",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const id = Number(req.body.id);
            const enabled = req.body.enabled ? 1 : 0;

            const target = db.getUserById(id);

            if (!target) {
                return res.status(404).json({
                    success: false,
                    message: "Usuário não encontrado"
                });
            }

            if (
                normalizeUsername(target.username) ===
                MASTER_OWNER
            ) {
                return res.status(400).json({
                    success: false,
                    message: "A conta master owner não pode ser desativada"
                });
            }

            db.prepare(`
                UPDATE users
                SET enabled = ?
                WHERE id = ?
            `).run(enabled, id);

            if (!enabled) {
                db.prepare(`
                    DELETE FROM sessions
                    WHERE user_id = ?
                `).run(id);
            }

            logAction(
                req.user.id,
                enabled
                    ? "enable_user"
                    : "disable_user",
                "user",
                String(id)
            );

            res.json({
                success: true,
                enabled: Boolean(enabled)
            });

        } catch (error) {
            console.error("Erro ao alterar usuário:", error);

            res.status(500).json({
                success: false,
                message: "Erro interno ao alterar usuário"
            });
        }
    }
);

/* =========================================================
   ADMIN - ALTERAR SENHA
========================================================= */

app.post(
    "/api/admin/users/password",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const id = Number(req.body.id);
            const password =
                String(req.body.password || "");

            if (!Number.isInteger(id) || id <= 0) {
                return res.status(400).json({
                    success: false,
                    message: "ID de usuário inválido"
                });
            }

            if (password.length < 8) {
                return res.status(400).json({
                    success: false,
                    message: "A senha precisa ter pelo menos 8 caracteres"
                });
            }

            const target = db.getUserById(id);

            if (!target) {
                return res.status(404).json({
                    success: false,
                    message: "Usuário não encontrado"
                });
            }

            const { salt, hash } =
                hashPassword(password);

            db.prepare(`
                UPDATE users
                SET
                    password_hash = ?,
                    password_salt = ?
                WHERE id = ?
            `).run(hash, salt, id);

            db.prepare(`
                DELETE FROM sessions
                WHERE user_id = ?
            `).run(id);

            logAction(
                req.user.id,
                "change_user_password",
                "user",
                String(id)
            );

            res.json({
                success: true,
                message: "Senha alterada com sucesso"
            });

        } catch (error) {
            console.error("Erro ao alterar senha:", error);

            res.status(500).json({
                success: false,
                message: "Erro interno ao alterar senha"
            });
        }
    }
);

/* =========================================================
   ADMIN - EXCLUIR CONTA
========================================================= */

app.delete(
    "/api/admin/users/delete",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const id = Number(req.body.id);
            const target = db.getUserById(id);

            if (!target) {
                return res.status(404).json({
                    success: false,
                    message: "Usuário não encontrado"
                });
            }

            if (
                normalizeUsername(target.username) ===
                MASTER_OWNER
            ) {
                return res.status(400).json({
                    success: false,
                    message: "A conta master owner não pode ser excluída"
                });
            }

            logAction(
                req.user.id,
                "delete_user",
                "user",
                String(id)
            );

            db.prepare(`
                DELETE FROM users
                WHERE id = ?
            `).run(id);

            res.json({
                success: true,
                message: "Usuário excluído com sucesso"
            });

        } catch (error) {
            console.error("Erro ao excluir usuário:", error);

            res.status(500).json({
                success: false,
                message: "Erro interno ao excluir usuário"
            });
        }
    }
);

/* =========================================================
   KEYS - GERAR 1 A 100 POR VEZ
========================================================= */

app.post(
    "/api/keys/generate",
    authRequired,
    (req, res) => {
        try {
            const prefix =
                sanitizePrefix(
                    req.body.prefix ||
                    "EXTERNAL"
                );

            const plan =
                String(req.body.plan || "1d");

            const quantity =
                req.body.quantity === undefined
                    ? 1
                    : Number(req.body.quantity);

            if (
                !Number.isInteger(quantity) ||
                quantity < 1 ||
                quantity > MAX_KEYS_PER_REQUEST
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        `A quantidade deve ser entre 1 e ${MAX_KEYS_PER_REQUEST}`
                });
            }

            const plans = {
                "1d": 1,
                "7d": 7,
                "30d": 30
            };

            let days;

            if (
                Object.prototype.hasOwnProperty.call(
                    plans,
                    plan
                )
            ) {
                days = plans[plan];

            } else if (plan === "custom") {
                days = Number(req.body.days);

                if (
                    !Number.isInteger(days) ||
                    days <= 0 ||
                    days > 36500
                ) {
                    return res.status(400).json({
                        success: false,
                        message: "Quantidade de dias inválida"
                    });
                }

            } else {
                return res.status(400).json({
                    success: false,
                    message: "Plano inválido"
                });
            }

            const freshUser =
                refreshAccountStatus(
                    db.getUserById(req.user.id)
                );

            const limit =
                freshUser.key_limit === null ||
                freshUser.key_limit === undefined
                    ? null
                    : Number(freshUser.key_limit);

            const alreadyGenerated =
                Number(
                    freshUser.keys_generated || 0
                );

            if (
                limit !== null &&
                alreadyGenerated + quantity > limit
            ) {
                return res.status(403).json({
                    success: false,
                    code: "KEY_LIMIT_EXCEEDED",
                    message:
                        "Essa geração ultrapassa o limite de keys da conta",
                    key_limit: limit,
                    keys_generated: alreadyGenerated,
                    keys_remaining:
                        Math.max(
                            0,
                            limit - alreadyGenerated
                        )
                });
            }

            const insert = db.prepare(`
                INSERT INTO keys (
                    key,
                    prefix,
                    status,
                    expires_at,
                    last_reset_at,
                    activated_at,
                    paused_at,
                    remaining_ms,
                    device_udid,
                    device_bound_at,
                    device_reset_at,
                    created_by_user_id
                )
                VALUES (
                    ?, ?,
                    'unused',
                    NULL,
                    ?,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    ?
                )
            `);

            const createBatch = db.transaction(() => {
                const generated = [];

                for (let i = 0; i < quantity; i++) {
                    let key;

                    do {
                        key =
                            generateKeyValue(prefix);
                    } while (
                        db.prepare(`
                            SELECT id
                            FROM keys
                            WHERE key = ?
                        `).get(key)
                    );

                    insert.run(
                        key,
                        prefix,
                        `PLAN:${days}`,
                        freshUser.id
                    );

                    generated.push(key);
                }

                db.prepare(`
                    UPDATE users
                    SET keys_generated =
                        COALESCE(keys_generated, 0) + ?
                    WHERE id = ?
                `).run(
                    quantity,
                    freshUser.id
                );

                return generated;
            });

            const keys = createBatch();

            for (const key of keys) {
                logAction(
                    freshUser.id,
                    "generate_key",
                    "key",
                    key
                );
            }

            const updatedUser =
                db.getUserById(freshUser.id);

            const usage =
                accountPublic(updatedUser);

            res.json({
                success: true,

                key:
                    keys.length === 1
                        ? keys[0]
                        : undefined,

                keys,
                quantity: keys.length,

                prefix,
                plan,
                days,
                status: "unused",

                usage: {
                    key_limit:
                        usage.key_limit,
                    keys_generated:
                        usage.keys_generated,
                    keys_remaining:
                        usage.keys_remaining,
                    unlimited:
                        usage.unlimited_keys
                }
            });

        } catch (error) {
            console.error("Erro ao gerar key:", error);

            res.status(500).json({
                success: false,
                message: "Erro interno ao gerar key"
            });
        }
    }
);

/* =========================================================
   KEY CHECK - PÚBLICO
========================================================= */


/* =========================================================
   CHECK KEY - PAINEL ADMIN
   PRIVADO - NÃO APLICA DEVICE_MISMATCH
========================================================= */

app.post(
    "/api/admin/keys/check",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(req.body.key || "").trim();

            if (!key) {
                return res.status(400).json({
                    success: false,
                    message: "Key não informada"
                });
            }

            const keyData = getAccessibleKey(key, req.user);

            if (!keyData) {
                return res.json({
                    success: true,
                    found: false,
                    message: "Key não encontrada"
                });
            }

            const status =
                checkKeyExpiration(keyData);

            return res.json({
                success: true,
                found: true,

                key: keyData.key,
                prefix: keyData.prefix,
                status,
                days:
                    getDaysFromKey(keyData),

                created_at:
                    keyData.created_at,
                activated_at:
                    keyData.activated_at,
                expires_at:
                    keyData.expires_at,
                paused_at:
                    keyData.paused_at,
                remaining_ms:
                    keyData.remaining_ms,

                device_bound:
                    Boolean(keyData.device_udid),
                device_udid:
                    keyData.device_udid || null,
                device_bound_at:
                    keyData.device_bound_at,

                created_by_username:
                    keyData.created_by_username ||
                    keyData.created_by ||
                    null
            });

        } catch (error) {
            console.error(
                "Erro ao consultar key no painel:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Erro interno ao consultar key"
            });
        }
    }
);

app.post("/api/keys/check", (req, res) => {
    try {
        const key =
            String(req.body.key || "").trim();

        const deviceToken =
            normalizeDeviceToken(
                req.body.device_token
            );

        /*
         * O painel web usa a mesma rota para consultar keys,
         * mas está autenticado com Bearer token.
         * Bloqueio DEVICE_MISMATCH é exclusivo do cliente
         * público/ExternalAuth, não do painel administrativo.
         */
        const isExternalAuthRequest =
            Object.prototype.hasOwnProperty.call(
                req.body || {},
                "device_token"
            );

        if (!key) {
            return res.status(400).json({
                success: false,
                message: "Key não informada"
            });
        }

        const keyData = getKey(key);

        if (!keyData) {
            return res.json({
                success: true,
                found: false,
                message: "Key não encontrada"
            });
        }

        const status =
            checkKeyExpiration(keyData);

        if (
            isExternalAuthRequest &&
            status === "active" &&
            keyData.device_udid &&
            keyData.device_token_hash &&
            !deviceTokenMatches(
                keyData,
                deviceToken
            )
        ) {
            return res.status(403).json({
                success: false,
                found: true,
                code: "DEVICE_MISMATCH",
                message:
                    "Essa key ja foi usada em outro dispositivo."
            });
        }

        return res.json({
            success: true,
            found: true,

            key: keyData.key,
            prefix: keyData.prefix,
            status,
            days:
                getDaysFromKey(keyData),

            created_at:
                keyData.created_at,
            activated_at:
                keyData.activated_at,
            expires_at:
                keyData.expires_at,
            paused_at:
                keyData.paused_at,
            remaining_ms:
                keyData.remaining_ms,

            device_bound:
                Boolean(
                    keyData.device_udid
                ),
            device_bound_at:
                keyData.device_bound_at,

            device_proof_required:
                Boolean(
                    keyData.device_udid &&
                    !keyData.device_token_hash
                )
        });

    } catch (error) {
        console.error(
            "Erro ao verificar key:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Erro interno ao verificar key"
        });
    }
});

/* =========================================================
   UDID - BIND
========================================================= */

app.post("/api/keys/device/bind", (req, res) => {
    try {
        const key =
            String(req.body.key || "").trim();

        const udid =
            normalizeUDID(req.body.udid);

        if (!key || !udid) {
            return res.status(400).json({
                success: false,
                message: "Key e UDID são obrigatórios"
            });
        }

        if (!validUDID(udid)) {
            return res.status(400).json({
                success: false,
                message: "UDID inválido"
            });
        }

        const keyData = getKey(key);

        if (!keyData) {
            return res.status(404).json({
                success: false,
                message: "Key não encontrada"
            });
        }

        const status =
            checkKeyExpiration(keyData);

        if (status === "expired") {
            return res.status(400).json({
                success: false,
                message: "Key expirada"
            });
        }

        if (status === "paused") {
            return res.status(400).json({
                success: false,
                message: "Key pausada"
            });
        }

        if (keyData.device_udid) {
            const saved =
                normalizeUDID(
                    keyData.device_udid
                );

            if (saved !== udid) {
                return res.status(403).json({
                    success: false,
                    code: "DEVICE_MISMATCH",
                    message:
                        "Key usada em outro dispositivo."
                });
            }

            return res.json({
                success: true,
                already_bound: true,
                device_match: true,
                message: "Dispositivo já vinculado"
            });
        }

        const boundAt = nowISO();

        const update = db.prepare(`
            UPDATE keys
            SET
                device_udid = ?,
                device_bound_at = ?,
                device_reset_at = NULL
            WHERE key = ?
              AND device_udid IS NULL
        `).run(
            udid,
            boundAt,
            keyData.key
        );

        if (update.changes !== 1) {
            const latest =
                getKey(keyData.key);

            if (
                latest &&
                latest.device_udid &&
                normalizeUDID(
                    latest.device_udid
                ) !== udid
            ) {
                return res.status(403).json({
                    success: false,
                    code: "DEVICE_MISMATCH",
                    message:
                        "Key usada em outro dispositivo."
                });
            }
        }

        res.json({
            success: true,
            already_bound: false,
            device_match: true,
            device_bound_at: boundAt,
            message:
                "Dispositivo vinculado com sucesso"
        });

    } catch (error) {
        console.error("Erro ao vincular UDID:", error);

        res.status(500).json({
            success: false,
            message:
                "Erro interno ao vincular dispositivo"
        });
    }
});

/* =========================================================
   UDID - VERIFY
========================================================= */

app.post("/api/keys/device/verify", (req, res) => {
    try {
        const key =
            String(req.body.key || "").trim();

        const udid =
            normalizeUDID(req.body.udid);

        if (!key || !udid) {
            return res.status(400).json({
                success: false,
                message: "Key e UDID são obrigatórios"
            });
        }

        const keyData = getKey(key);

        if (!keyData) {
            return res.status(404).json({
                success: false,
                message: "Key não encontrada"
            });
        }

        if (!keyData.device_udid) {
            return res.status(409).json({
                success: false,
                code: "DEVICE_NOT_BOUND",
                message:
                    "Key ainda não possui dispositivo vinculado"
            });
        }

        if (
            normalizeUDID(
                keyData.device_udid
            ) !== udid
        ) {
            return res.status(403).json({
                success: false,
                code: "DEVICE_MISMATCH",
                message:
                    "Key usada em outro dispositivo."
            });
        }

        res.json({
            success: true,
            device_match: true
        });

    } catch (error) {
        console.error("Erro ao validar UDID:", error);

        res.status(500).json({
            success: false,
            message:
                "Erro interno ao validar dispositivo"
        });
    }
});

/* =========================================================
   ATIVAR KEY
========================================================= */

app.post("/api/keys/activate", (req, res) => {
    try {
        const key =
            String(req.body.key || "").trim();

        const udid =
            normalizeUDID(req.body.udid);

        if (!key) {
            return res.status(400).json({
                success: false,
                message: "Key não informada"
            });
        }

        const keyData = getKey(key);

        if (!keyData) {
            return res.status(404).json({
                success: false,
                message: "Key não encontrada"
            });
        }

        const status =
            checkKeyExpiration(keyData);

        if (status === "paused") {
            return res.status(400).json({
                success: false,
                message: "Key está pausada"
            });
        }

        if (status === "expired") {
            return res.status(400).json({
                success: false,
                message: "Key expirada"
            });
        }

        if (!keyData.device_udid) {
            return res.status(409).json({
                success: false,
                code: "DEVICE_NOT_BOUND",
                message:
                    "Obtenha e vincule o UDID antes de ativar a key"
            });
        }

        if (
            !udid ||
            normalizeUDID(
                keyData.device_udid
            ) !== udid
        ) {
            return res.status(403).json({
                success: false,
                code: "DEVICE_MISMATCH",
                message:
                    "Key usada em outro dispositivo."
            });
        }

        if (status === "active") {
            return res.json({
                success: true,
                key: keyData.key,
                status: "active",
                already_active: true,
                activated_at:
                    keyData.activated_at,
                expires_at:
                    keyData.expires_at,
                device_match: true
            });
        }

        if (status !== "unused") {
            return res.status(400).json({
                success: false,
                message: "Key não pode ser ativada"
            });
        }

        const days =
            getDaysFromKey(keyData);

        if (!days || days <= 0) {
            return res.status(400).json({
                success: false,
                message:
                    "Plano da key não encontrado"
            });
        }

        const activatedAt = nowISO();
        const expiresAt =
            calculateExpiration(days);

        db.prepare(`
            UPDATE keys
            SET
                status = 'active',
                activated_at = ?,
                expires_at = ?,
                paused_at = NULL,
                remaining_ms = NULL
            WHERE id = ?
        `).run(
            activatedAt,
            expiresAt,
            keyData.id
        );

        res.json({
            success: true,
            key: keyData.key,
            status: "active",
            days,
            activated_at: activatedAt,
            expires_at: expiresAt,
            device_match: true
        });

    } catch (error) {
        console.error("Erro ao ativar key:", error);

        res.status(500).json({
            success: false,
            message: "Erro interno ao ativar key"
        });
    }
});

/* =========================================================
   RESET KEY - LIBERAR DISPOSITIVO SEM ZERAR TEMPO
========================================================= */

app.post(
    "/api/keys/reset",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(req.body.key || "").trim();

            const keyData = getAccessibleKey(key, req.user);

            if (!keyData) {
                return res.status(404).json({
                    success: false,
                    message: "Key não encontrada"
                });
            }

            /*
             * Reset administrativo da key:
             * - preserva status/ativacao/expiracao/tempo restante
             * - remove vinculo de dispositivo e provas antigas
             * - permite que outro dispositivo vincule novamente
             */
            const resetAt = nowISO();

            db.prepare(`
                UPDATE keys
                SET
                    device_udid = NULL,
                    device_bound_at = NULL,
                    device_token_hash = NULL,
                    device_reset_at = ?
                WHERE id = ?
            `).run(
                resetAt,
                keyData.id
            );

            db.prepare(`
                DELETE FROM device_enrollments
                WHERE key_id = ?
            `).run(keyData.id);

            const fresh = getKey(keyData.key);
            const status = checkKeyExpiration(fresh);

            logAction(
                req.user.id,
                "reset_key_device_info",
                "key",
                keyData.key
            );

            res.json({
                success: true,
                message: "Informações de dispositivo resetadas. O tempo da key foi preservado.",
                key: keyData.key,
                status,
                days: getDaysFromKey(fresh),
                activated_at: fresh.activated_at,
                expires_at: fresh.expires_at,
                paused_at: fresh.paused_at,
                remaining_ms: fresh.remaining_ms,
                device_bound: false,
                device_reset_at: resetAt
            });

        } catch (error) {
            console.error("Erro ao resetar informações da key:", error);

            res.status(500).json({
                success: false,
                message: "Erro interno ao resetar informações da key"
            });
        }
    }
);

/* =========================================================
   RESET UDID
========================================================= */

app.post(
    "/api/keys/device/reset",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(req.body.key || "").trim();

            const keyData = getAccessibleKey(key, req.user);

            if (!keyData) {
                return res.status(404).json({
                    success: false,
                    message: "Key não encontrada"
                });
            }

            const resetAt = nowISO();

            db.prepare(`
                UPDATE keys
                SET
                    device_udid = NULL,
                    device_bound_at = NULL,
                    device_token_hash = NULL,
                    device_reset_at = ?
                WHERE id = ?
            `).run(
                resetAt,
                keyData.id
            );

            db.prepare(`
                DELETE FROM device_enrollments
                WHERE key_id = ?
            `).run(keyData.id);

            logAction(
                req.user.id,
                "reset_udid",
                "key",
                keyData.key
            );

            res.json({
                success: true,
                message: "UDID resetado com sucesso",
                key: keyData.key,
                device_bound: false,
                device_reset_at: resetAt
            });

        } catch (error) {
            console.error("Erro ao resetar UDID:", error);

            res.status(500).json({
                success: false,
                message:
                    "Erro interno ao resetar UDID"
            });
        }
    }
);

/* =========================================================
   PAUSAR KEY
========================================================= */

app.post(
    "/api/keys/pause",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(req.body.key || "").trim();

            const keyData = getAccessibleKey(key, req.user);

            if (!keyData) {
                return res.status(404).json({
                    success: false,
                    message: "Key não encontrada"
                });
            }

            if (
                checkKeyExpiration(keyData) !==
                "active"
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Somente keys ativas podem ser pausadas"
                });
            }

            const remaining =
                new Date(
                    keyData.expires_at
                ).getTime() -
                Date.now();

            if (remaining <= 0) {
                db.prepare(`
                    UPDATE keys
                    SET status = 'expired'
                    WHERE id = ?
                `).run(keyData.id);

                return res.status(400).json({
                    success: false,
                    message: "Key já está expirada"
                });
            }

            const pausedAt = nowISO();

            db.prepare(`
                UPDATE keys
                SET
                    status = 'paused',
                    paused_at = ?,
                    remaining_ms = ?,
                    expires_at = NULL
                WHERE id = ?
            `).run(
                pausedAt,
                remaining,
                keyData.id
            );

            logAction(
                req.user.id,
                "pause_key",
                "key",
                keyData.key
            );

            res.json({
                success: true,
                message: "Key pausada com sucesso",
                key: keyData.key,
                status: "paused",
                paused_at: pausedAt,
                remaining_ms: remaining
            });

        } catch (error) {
            console.error("Erro ao pausar key:", error);

            res.status(500).json({
                success: false,
                message:
                    "Erro interno ao pausar key"
            });
        }
    }
);

/* =========================================================
   RETOMAR KEY
========================================================= */

app.post(
    "/api/keys/resume",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(req.body.key || "").trim();

            const keyData = getAccessibleKey(key, req.user);

            if (!keyData) {
                return res.status(404).json({
                    success: false,
                    message: "Key não encontrada"
                });
            }

            if (
                keyData.status !== "paused" ||
                !keyData.remaining_ms ||
                Number(keyData.remaining_ms) <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Key não está pausada ou não possui tempo restante"
                });
            }

            const expiresAt =
                new Date(
                    Date.now() +
                    Number(
                        keyData.remaining_ms
                    )
                ).toISOString();

            db.prepare(`
                UPDATE keys
                SET
                    status = 'active',
                    expires_at = ?,
                    paused_at = NULL,
                    remaining_ms = NULL
                WHERE id = ?
            `).run(
                expiresAt,
                keyData.id
            );

            logAction(
                req.user.id,
                "resume_key",
                "key",
                keyData.key
            );

            res.json({
                success: true,
                message: "Key retomada com sucesso",
                key: keyData.key,
                status: "active",
                expires_at: expiresAt
            });

        } catch (error) {
            console.error("Erro ao retomar key:", error);

            res.status(500).json({
                success: false,
                message:
                    "Erro interno ao retomar key"
            });
        }
    }
);

/* =========================================================
   PAUSAR TODAS AS KEYS - OWNER
========================================================= */

app.post(
    "/api/admin/keys/pause-all",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const rows = db.prepare(`
                SELECT *
                FROM keys
                WHERE status = 'active'
                ORDER BY id ASC
            `).all();

            let paused = 0;
            let expired = 0;

            const tx = db.transaction(() => {
                for (const keyData of rows) {
                    const status = checkKeyExpiration(keyData);

                    if (status === "expired") {
                        expired += 1;
                        continue;
                    }

                    if (status !== "active") {
                        continue;
                    }

                    const expiresAt = keyData.expires_at
                        ? new Date(keyData.expires_at).getTime()
                        : 0;

                    const remaining = expiresAt
                        ? Math.max(0, expiresAt - Date.now())
                        : 0;

                    if (remaining <= 0) {
                        db.prepare(`
                            UPDATE keys
                            SET status = 'expired'
                            WHERE id = ?
                        `).run(keyData.id);
                        expired += 1;
                        continue;
                    }

                    db.prepare(`
                        UPDATE keys
                        SET
                            status = 'paused',
                            paused_at = ?,
                            remaining_ms = ?
                        WHERE id = ?
                    `).run(
                        nowISO(),
                        remaining,
                        keyData.id
                    );

                    paused += 1;
                }
            });

            tx();

            logAction(
                req.user.id,
                "pause_all_keys",
                "keys",
                String(paused)
            );

            return res.json({
                success: true,
                paused,
                expired,
                message:
                    paused === 1
                        ? "1 key foi pausada."
                        : `${paused} keys foram pausadas.`
            });

        } catch (error) {
            console.error("Erro ao pausar todas as keys:", error);

            return res.status(500).json({
                success: false,
                message: "Erro interno ao pausar todas as keys"
            });
        }
    }
);

/* =========================================================
   DELETAR KEY
========================================================= */

app.delete(
    "/api/keys/delete",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(req.body.key || "").trim();

            const keyData = getAccessibleKey(key, req.user);

            if (!keyData) {
                return res.status(404).json({
                    success: false,
                    message: "Key não encontrada"
                });
            }

            db.prepare(`
                DELETE FROM keys
                WHERE id = ?
            `).run(keyData.id);

            logAction(
                req.user.id,
                "delete_key",
                "key",
                keyData.key
            );

            res.json({
                success: true,
                message: "Key deletada com sucesso",
                key: keyData.key
            });

        } catch (error) {
            console.error("Erro ao deletar key:", error);

            res.status(500).json({
                success: false,
                message:
                    "Erro interno ao deletar key"
            });
        }
    }
);

/* =========================================================
   LISTAR KEYS
========================================================= */

app.get(
    "/api/keys",
    authRequired,
    (req, res) => {
        try {
            const rows = isKeyAdminUser(req.user)
                ? db.prepare(`
                    SELECT
                        keys.*,
                        users.username AS created_by_username
                    FROM keys
                    LEFT JOIN users
                        ON users.id =
                           keys.created_by_user_id
                    ORDER BY keys.id DESC
                `).all()
                : db.prepare(`
                    SELECT
                        keys.*,
                        users.username AS created_by_username
                    FROM keys
                    LEFT JOIN users
                        ON users.id =
                           keys.created_by_user_id
                    WHERE keys.created_by_user_id = ?
                    ORDER BY keys.id DESC
                `).all(req.user.id);

            const keys = rows.map(
                keyData => ({
                    ...keyData,
                    status:
                        checkKeyExpiration(
                            keyData
                        ),
                    days:
                        getDaysFromKey(
                            keyData
                        ),
                    device_bound:
                        Boolean(
                            keyData.device_udid
                        )
                })
            );

            res.json({
                success: true,
                total: keys.length,
                keys
            });

        } catch (error) {
            console.error("Erro ao listar keys:", error);

            res.status(500).json({
                success: false,
                message:
                    "Erro interno ao listar keys"
            });
        }
    }
);


/* =========================================================
   UDID S0N1C - INICIAR SESSÃO
========================================================= */

app.post(
    "/api/device/session",
    (req, res) => {
        try {
            const key =
                String(req.body.key || "").trim();

            if (!key) {
                return res.status(400).json({
                    success: false,
                    message: "Key não informada"
                });
            }

            const keyData = getKey(key);

            if (!keyData) {
                return res.status(404).json({
                    success: false,
                    message: "Key não encontrada"
                });
            }

            const status =
                checkKeyExpiration(keyData);

            if (status === "expired") {
                return res.status(400).json({
                    success: false,
                    message: "Key expirada"
                });
            }

            if (status === "paused") {
                return res.status(400).json({
                    success: false,
                    message: "Key pausada"
                });
            }

            const session =
                createDeviceEnrollmentSession(
                    keyData
                );

            return res.json({
                success: true,
                token: session.token,
                expires_at:
                    session.expiresAt,
                start_url:
                    `${PUBLIC_URL}/device/session/` +
                    `${encodeURIComponent(session.token)}/enroll`
            });

        } catch (error) {
            console.error(
                "Erro criando sessão UDID:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Erro interno ao criar sessão UDID"
            });
        }
    }
);

/* =========================================================
   UDID S0N1C - STATUS DA SESSÃO
========================================================= */

app.post(
    "/api/device/session/status",
    (req, res) => {
        try {
            const key =
                String(req.body.key || "").trim();

            const token =
                String(req.body.token || "").trim();

            if (!key || !token) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Key e token são obrigatórios"
                });
            }

            const enrollment =
                getDeviceEnrollment(token);

            if (
                !enrollment ||
                enrollment.key !== key
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Sessão UDID não encontrada"
                });
            }

            if (enrollmentIsExpired(enrollment)) {
                return res.status(410).json({
                    success: false,
                    expired: true,
                    message:
                        "Sessão UDID expirada"
                });
            }

            const keyData =
                getKey(enrollment.key);

            return res.json({
                success: true,
                completed:
                    enrollment.status ===
                    "completed",
                device_bound:
                    Boolean(
                        keyData &&
                        keyData.device_udid
                    ),
                key_status:
                    keyData
                        ? checkKeyExpiration(
                              keyData
                          )
                        : null,

                device_token:
                    enrollment.status ===
                    "completed"
                        ? enrollment.device_token
                        : null
            });

        } catch (error) {
            console.error(
                "Erro consultando sessão UDID:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Erro interno ao consultar sessão UDID"
            });
        }
    }
);

/* =========================================================
   UDID S0N1C - MIDDLEWARE
========================================================= */

let UDIDFetcherClassPromise = null;
const deviceFetcherCache = new Map();

function getUDIDFetcherClass() {
    if (!UDIDFetcherClassPromise) {
        UDIDFetcherClassPromise =
            import("udid-fetcher")
                .then(module => {
                    const candidates = [
                        module?.default?.default,
                        module?.default?.UDIDFetcher,
                        module?.default,
                        module?.UDIDFetcher,
                        module
                    ];

                    const exported =
                        candidates.find(
                            candidate =>
                                typeof candidate ===
                                "function"
                        );

                    if (!exported) {
                        console.error(
                            "Exports disponíveis em udid-fetcher:",
                            Object.keys(module || {}),
                            module?.default &&
                            typeof module.default === "object"
                                ? Object.keys(
                                      module.default
                                  )
                                : null
                        );

                        throw new Error(
                            "Export de udid-fetcher inválido"
                        );
                    }

                    return exported;
                });
    }

    return UDIDFetcherClassPromise;
}

function trimDeviceFetcherCache() {
    while (
        deviceFetcherCache.size >
        DEVICE_FETCHER_CACHE_LIMIT
    ) {
        const firstKey =
            deviceFetcherCache.keys().next().value;

        if (!firstKey) {
            break;
        }

        deviceFetcherCache.delete(firstKey);
    }
}


function decodeProfileXmlEntity(value) {
    return String(value || "")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '\"')
        .replace(/&apos;/g, "'")
        .replace(/&amp;/g, "&");
}

function extractProfileString(xml, key) {
    const escapedKey = String(key)
        .replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    const pattern = new RegExp(
        "<key>\\s*" +
        escapedKey +
        "\\s*</key>\\s*<string>([\\s\\S]*?)</string>",
        "i"
    );

    const match =
        String(xml || "").match(pattern);

    return match
        ? decodeProfileXmlEntity(
            match[1]
        ).trim()
        : "";
}

function extractDeviceFromProfileBody(body, contentType = "") {
    if (!Buffer.isBuffer(body)) {
        if (typeof body === "string") {
            body = Buffer.from(body, "binary");
        } else {
            return null;
        }
    }

    function findPlistInBuffer(buffer) {
        if (!Buffer.isBuffer(buffer) || !buffer.length) {
            return null;
        }

        const candidates = [
            buffer.toString("utf8"),
            buffer.toString("latin1")
        ];

        for (const raw of candidates) {
            let start = raw.indexOf("<?xml");

            if (start < 0) {
                start = raw.indexOf("<plist");
            }

            if (start < 0) {
                continue;
            }

            const closeTag = "</plist>";
            const closeIndex =
                raw.indexOf(closeTag, start);

            if (closeIndex < 0) {
                continue;
            }

            return raw.slice(
                start,
                closeIndex + closeTag.length
            );
        }

        return null;
    }

    function deviceFromXml(xml) {
        if (!xml) {
            return null;
        }

        return {
            UDID:
                extractProfileString(xml, "UDID"),
            PRODUCT:
                extractProfileString(xml, "PRODUCT"),
            VERSION:
                extractProfileString(xml, "VERSION"),
            SERIAL:
                extractProfileString(xml, "SERIAL"),
            IMEI:
                extractProfileString(xml, "IMEI"),
            ICCID:
                extractProfileString(xml, "ICCID")
        };
    }

    // 1) Caso venha plist em claro.
    const directXml =
        findPlistInBuffer(body);

    if (directXml) {
        return deviceFromXml(directXml);
    }

    const normalizedType =
        String(contentType || "").toLowerCase();

    const isPkcs7 =
        normalizedType.includes(
            "application/pkcs7-signature"
        ) ||
        normalizedType.includes(
            "application/pkcs7-mime"
        );

    if (!isPkcs7) {
        return null;
    }

    /*
     * 2) Caminho principal: usa o OpenSSL do servidor para
     * desempacotar CMS/PKCS#7 SignedData e devolver o plist.
     *
     * O iPhone envia o retorno do Profile Service como DER
     * application/pkcs7-signature.
     */
    try {
        const decoded =
            execFileSync(
                "openssl",
                [
                    "cms",
                    "-verify",
                    "-inform",
                    "DER",
                    "-noverify",
                    "-binary"
                ],
                {
                    input: body,
                    encoding: null,
                    stdio: [
                        "pipe",
                        "pipe",
                        "pipe"
                    ],
                    maxBuffer:
                        2 * 1024 * 1024
                }
            );

        const xml =
            findPlistInBuffer(decoded);

        if (xml) {
            console.log(
                "PKCS#7 decodificado com OpenSSL:",
                {
                    decodedBytes:
                        decoded.length
                }
            );

            return deviceFromXml(xml);
        }

        console.error(
            "OpenSSL decodificou o CMS, mas o plist não apareceu.",
            {
                decodedBytes:
                    decoded?.length || 0
            }
        );
    } catch (error) {
        console.error(
            "OpenSSL CMS não conseguiu extrair o conteúdo:",
            error?.stderr
                ? Buffer
                    .from(error.stderr)
                    .toString("utf8")
                    .trim()
                : error?.message ||
                  String(error)
        );
    }

    /*
     * 3) Fallback node-forge.
     *
     * Além de olhar cada OCTET STRING isoladamente,
     * concatena todos os valores binários porque alguns
     * SignedData dividem o plist em vários blocos ASN.1.
     */
    try {
        const der =
            forge.util.createBuffer(
                body.toString("binary"),
                "binary"
            );

        const root =
            forge.asn1.fromDer(
                der,
                false
            );

        const chunks = [];
        let xml = null;

        function walk(node) {
            if (!node) {
                return;
            }

            if (Array.isArray(node.value)) {
                for (const child of node.value) {
                    walk(child);
                }

                return;
            }

            if (
                typeof node.value ===
                "string"
            ) {
                const candidate =
                    Buffer.from(
                        node.value,
                        "binary"
                    );

                chunks.push(candidate);

                if (!xml) {
                    xml =
                        findPlistInBuffer(
                            candidate
                        );
                }
            }
        }

        walk(root);

        if (!xml && chunks.length) {
            /*
             * Testa concatenação total e também janelas de
             * chunks consecutivos. Isso cobre eContent
             * fragmentado em múltiplos OCTET STRING.
             */
            const combined =
                Buffer.concat(chunks);

            xml =
                findPlistInBuffer(
                    combined
                );

            if (!xml) {
                for (
                    let i = 0;
                    i < chunks.length && !xml;
                    i++
                ) {
                    const window = [];

                    for (
                        let j = i;
                        j < chunks.length &&
                        j < i + 12;
                        j++
                    ) {
                        window.push(
                            chunks[j]
                        );

                        xml =
                            findPlistInBuffer(
                                Buffer.concat(
                                    window
                                )
                            );

                        if (xml) {
                            break;
                        }
                    }
                }
            }
        }

        if (!xml) {
            try {
                const message =
                    forge.pkcs7
                        .messageFromAsn1(root);

                if (
                    message &&
                    message.content
                ) {
                    let bytes = null;

                    if (
                        typeof message.content
                            .getBytes ===
                        "function"
                    ) {
                        bytes =
                            message.content
                                .getBytes();
                    } else if (
                        typeof message.content
                            .bytes ===
                        "function"
                    ) {
                        bytes =
                            message.content
                                .bytes();
                    } else if (
                        typeof message.content ===
                        "string"
                    ) {
                        bytes =
                            message.content;
                    }

                    if (bytes !== null) {
                        xml =
                            findPlistInBuffer(
                                Buffer.from(
                                    bytes,
                                    "binary"
                                )
                            );
                    }
                }
            } catch (pkcs7Error) {
                console.error(
                    "Fallback PKCS#7 do node-forge falhou:",
                    pkcs7Error?.message ||
                    String(pkcs7Error)
                );
            }
        }

        if (!xml) {
            console.error(
                "PKCS#7 recebido, mas nenhum plist XML foi localizado após OpenSSL e node-forge."
            );

            return null;
        }

        console.log(
            "PKCS#7 decodificado pelo fallback node-forge."
        );

        return deviceFromXml(xml);

    } catch (error) {
        console.error(
            "Falha final decodificando PKCS#7:",
            error
        );

        return null;
    }
}

/*
 * Compatibilidade com iOS atual:
 * trata o POST /confirm antes do udid-fetcher antigo.
 *
 * O pacote antigo tenta analisar o corpo binário inteiro como XML,
 * o que causa o erro do xmldom. Aqui extraímos somente o plist XML
 * contido na resposta do Profile Service.
 */
app.post(
    "/device/session/:token/confirm",
    express.raw({
        type: "*/*",
        limit: "1mb"
    }),
    (req, res) => {
        try {
            const token =
                String(req.params.token || "").trim();

            const queryToken =
                String(req.query.token || "").trim();

            if (
                queryToken &&
                queryToken !== token
            ) {
                return res
                    .status(400)
                    .type("text/plain")
                    .send("Token de sessão inválido.");
            }

            const enrollment =
                getDeviceEnrollment(token);

            if (!enrollment) {
                return res
                    .status(404)
                    .type("text/plain")
                    .send(
                        "Sessão UDID não encontrada."
                    );
            }

            if (enrollmentIsExpired(enrollment)) {
                deviceFetcherCache.delete(token);

                return res
                    .status(410)
                    .type("text/plain")
                    .send(
                        "Sessão UDID expirada. Volte ao app e tente novamente."
                    );
            }

            if (
                enrollment.status ===
                "completed"
            ) {
                return res.redirect(
                    302,
                    `${PUBLIC_URL}/device/success?token=` +
                    encodeURIComponent(token)
                );
            }

            const body =
                Buffer.isBuffer(req.body)
                    ? req.body
                    : Buffer.alloc(0);

            console.log(
                "UDID confirm recebido:",
                {
                    token:
                        token.slice(0, 8) + "...",
                    contentType:
                        req.headers[
                            "content-type"
                        ] || null,
                    bytes: body.length
                }
            );

            const device =
                extractDeviceFromProfileBody(
                    body,
                    req.headers[
                        "content-type"
                    ] || ""
                );

            if (device) {
                console.log(
                    "Plist UDID extraído:",
                    {
                        hasUDID:
                            Boolean(device.UDID),
                        product:
                            device.PRODUCT || "",
                        version:
                            device.VERSION || ""
                    }
                );
            }

            if (!device) {
                console.error(
                    "Não foi possível localizar plist XML no retorno UDID.",
                    {
                        contentType:
                            req.headers[
                                "content-type"
                            ] || null,
                        bytes: body.length
                    }
                );

                return res
                    .status(400)
                    .type("text/plain")
                    .send(
                        "Resposta do dispositivo não pôde ser processada."
                    );
            }

            const udid =
                normalizeUDID(device.UDID);

            const product =
                String(
                    device.PRODUCT || ""
                ).trim();

            const iosVersion =
                String(
                    device.VERSION || ""
                ).trim();

            if (
                !udid ||
                !validUDID(udid)
            ) {
                console.error(
                    "Resposta UDID sem UDID válido:",
                    {
                        product,
                        version: iosVersion,
                        hasUDID:
                            Boolean(device.UDID)
                    }
                );

                return res
                    .status(400)
                    .type("text/plain")
                    .send(
                        "Não foi possível obter um UDID válido."
                    );
            }

            const latestEnrollment =
                getDeviceEnrollment(token);

            if (
                !latestEnrollment ||
                enrollmentIsExpired(
                    latestEnrollment
                )
            ) {
                deviceFetcherCache.delete(token);

                return res
                    .status(410)
                    .type("text/plain")
                    .send(
                        "Sessão UDID expirada."
                    );
            }

            const keyData =
                getKey(latestEnrollment.key);

            if (!keyData) {
                return res
                    .status(404)
                    .type("text/plain")
                    .send(
                        "Key da sessão não encontrada."
                    );
            }

            activateKeyAfterDeviceEnrollment(
                keyData,
                udid
            );

            const completedKey =
                getKey(
                    latestEnrollment.key
                );

            issueDeviceTokenForEnrollment(
                completedKey,
                latestEnrollment.id
            );

            db.prepare(`
                UPDATE device_enrollments
                SET
                    status = 'completed',
                    udid = ?,
                    product = ?,
                    ios_version = ?,
                    completed_at = ?
                WHERE id = ?
                  AND status = 'pending'
            `).run(
                udid,
                product || null,
                iosVersion || null,
                nowISO(),
                latestEnrollment.id
            );

            deviceFetcherCache.delete(token);

            console.log(
                "UDID vinculado com sucesso:",
                {
                    enrollmentId:
                        latestEnrollment.id,
                    product:
                        product || null,
                    version:
                        iosVersion || null
                }
            );

            return res.redirect(
                302,
                `${PUBLIC_URL}/device/success?token=` +
                encodeURIComponent(token)
            );

        } catch (error) {
            console.error(
                "Erro no confirm UDID:",
                error
            );

            if (
                error &&
                error.code ===
                    "DEVICE_MISMATCH"
            ) {
                return res
                    .status(403)
                    .type("text/plain")
                    .send(
                        "Essa key já está vinculada a outro dispositivo."
                    );
            }

            return res
                .status(500)
                .type("text/plain")
                .send(
                    "Não foi possível vincular o dispositivo."
                );
        }
    }
);

app.use(
    "/device/session/:token",
    async (req, res, next) => {
        try {
            const token =
                String(
                    req.params.token || ""
                ).trim();

            const enrollment =
                getDeviceEnrollment(token);

            if (!enrollment) {
                return res.status(404).send(
                    "Sessão UDID não encontrada."
                );
            }

            if (enrollmentIsExpired(enrollment)) {
                deviceFetcherCache.delete(token);

                return res.status(410).send(
                    "Sessão UDID expirada. Volte ao app e tente novamente."
                );
            }

            const UDIDFetcher =
                await getUDIDFetcherClass();

            let fetcher =
                deviceFetcherCache.get(token);

            if (!fetcher) {
                const baseURL =
                    `${PUBLIC_URL}/device/session/` +
                    `${encodeURIComponent(token)}/`;

                fetcher = new UDIDFetcher({
                    name: "EXTERNAL Device",
                    description:
                        "Vincula este iPhone à sua licença.",
                    identifier:
                        "app.external.device",
                    organization:
                        "EXTERNAL",
                    apiURL: baseURL,
                    query: {
                        token
                    },
                    done: (
                        callbackReq,
                        callbackRes
                    ) => {
                        try {
                            const callbackToken =
                                String(
                                    callbackReq.query
                                        .token || ""
                                ).trim();

                            if (
                                callbackToken !==
                                token
                            ) {
                                return callbackRes
                                    .status(400)
                                    .send(
                                        "Token de sessão inválido."
                                    );
                            }

                            const latestEnrollment =
                                getDeviceEnrollment(
                                    token
                                );

                            if (
                                !latestEnrollment ||
                                enrollmentIsExpired(
                                    latestEnrollment
                                )
                            ) {
                                deviceFetcherCache.delete(
                                    token
                                );

                                return callbackRes
                                    .status(410)
                                    .send(
                                        "Sessão UDID expirada."
                                    );
                            }

                            if (
                                latestEnrollment.status ===
                                "completed"
                            ) {
                                return callbackRes.redirect(
                                    302,
                                    `${PUBLIC_URL}/device/success?token=` +
                                    encodeURIComponent(
                                        token
                                    )
                                );
                            }

                            const device =
                                callbackReq.device ||
                                {};

                            const udid =
                                normalizeUDID(
                                    deviceValue(
                                        device,
                                        "udid",
                                        "UDID",
                                        "Udid"
                                    )
                                );

                            const product =
                                deviceValue(
                                    device,
                                    "product",
                                    "PRODUCT",
                                    "model",
                                    "MODEL"
                                );

                            const iosVersion =
                                deviceValue(
                                    device,
                                    "version",
                                    "VERSION",
                                    "iosVersion",
                                    "OS_VERSION"
                                );

                            if (
                                !udid ||
                                !validUDID(udid)
                            ) {
                                console.error(
                                    "Resposta UDID inválida:",
                                    device
                                );

                                return callbackRes
                                    .status(400)
                                    .send(
                                        "Não foi possível obter um UDID válido."
                                    );
                            }

                            const keyData =
                                getKey(
                                    latestEnrollment
                                        .key
                                );

                            activateKeyAfterDeviceEnrollment(
                                keyData,
                                udid
                            );

                            const completedKey =
                                getKey(
                                    latestEnrollment.key
                                );

                            issueDeviceTokenForEnrollment(
                                completedKey,
                                latestEnrollment.id
                            );

                            db.prepare(`
                                UPDATE device_enrollments
                                SET
                                    status = 'completed',
                                    udid = ?,
                                    product = ?,
                                    ios_version = ?,
                                    completed_at = ?
                                WHERE id = ?
                                  AND status = 'pending'
                            `).run(
                                udid,
                                product || null,
                                iosVersion || null,
                                nowISO(),
                                latestEnrollment.id
                            );

                            deviceFetcherCache.delete(
                                token
                            );

                            return callbackRes.redirect(
                                302,
                                `${PUBLIC_URL}/device/success?token=` +
                                encodeURIComponent(
                                    token
                                )
                            );

                        } catch (error) {
                            console.error(
                                "Erro finalizando UDID:",
                                error
                            );

                            if (
                                error &&
                                error.code ===
                                    "DEVICE_MISMATCH"
                            ) {
                                return callbackRes
                                    .status(403)
                                    .send(
                                        "Essa key já está vinculada a outro dispositivo."
                                    );
                            }

                            return callbackRes
                                .status(500)
                                .send(
                                    "Não foi possível vincular o dispositivo."
                                );
                        }
                    }
                });

                deviceFetcherCache.set(
                    token,
                    fetcher
                );

                trimDeviceFetcherCache();
            }

            return fetcher.router(
                req,
                res,
                next
            );

        } catch (error) {
            console.error("Erro no UDID Fetcher:", error);

            return res
                .status(500)
                .type("text/plain")
                .send(
                    "ERRO UDID:\n\n" +
                    (error?.stack || error?.message || String(error))
                );
        }
    }
);

/* =========================================================
   UDID S0N1C - PÁGINA DE SUCESSO
========================================================= */

app.get(
    "/device/success",
    (req, res) => {
        const token =
            String(req.query.token || "").trim();

        const enrollment =
            token
                ? getDeviceEnrollment(token)
                : null;

        const completed =
            Boolean(
                enrollment &&
                enrollment.status === "completed"
            );

        return res
            .status(completed ? 200 : 400)
            .type("html")
            .send(`<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>EXTERNAL</title>
<style>
html,body{margin:0;min-height:100%;background:#090909;color:#fff;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display",Arial,sans-serif}
body{display:flex;align-items:center;justify-content:center;padding:24px;box-sizing:border-box}
.card{width:min(420px,100%);padding:28px;border:1px solid rgba(255,255,255,.16);border-radius:28px;background:rgba(255,255,255,.07);backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px);box-shadow:0 24px 80px rgba(0,0,0,.45);text-align:center}
h1{font-size:24px;margin:0 0 10px}
p{margin:0;color:rgba(255,255,255,.68);line-height:1.45}
</style>
</head>
<body>
<div class="card">
<h1>${completed ? "Dispositivo vinculado" : "Sessão inválida"}</h1>
<p>${completed ? "Volte para o aplicativo para continuar." : "Volte para o aplicativo e gere uma nova sessão de UDID."}</p>
</div>
</body>
</html>`);
    }
);


/* =========================================================
   REVENDEDOR - CADASTRO / LOGIN
========================================================= */

/* =========================================================
   MASTER OWNER - ADMINISTRAR REVENDEDORES
========================================================= */

app.get(
    "/api/admin/resellers",
    authRequired,
    masterOwnerRequired,
    (req, res) => {
        try {
            const rows = db.prepare(`
                SELECT
                    r.*,
                    (
                        SELECT COUNT(*)
                        FROM reseller_keys rk
                        WHERE rk.reseller_id = r.id
                    ) AS keys_generated,
                    (
                        SELECT COALESCE(SUM(rd.amount_cents), 0)
                        FROM reseller_deposits rd
                        WHERE rd.reseller_id = r.id
                          AND rd.credited = 1
                    ) AS credited_deposits_cents
                FROM resellers r
                ORDER BY r.id DESC
            `).all();

            const resellers = rows.map(row => ({
                ...resellerPublic(row),
                keys_generated: Number(row.keys_generated || 0),
                credited_deposits:
                    Number(row.credited_deposits_cents || 0) / 100
            }));

            return res.json({
                success: true,
                total: resellers.length,
                resellers
            });
        } catch (error) {
            console.error("Erro ao listar revendedores:", error);
            return res.status(500).json({
                success: false,
                message: "Erro interno ao listar revendedores"
            });
        }
    }
);

app.post(
    "/api/admin/resellers/update",
    authRequired,
    masterOwnerRequired,
    (req, res) => {
        try {
            const id = Number(req.body.id);
            const username = normalizeUsername(req.body.username);
            const email = String(req.body.email || "").trim().toLowerCase();

            if (!Number.isInteger(id) || id <= 0) {
                return res.status(400).json({success:false,message:"ID inválido"});
            }

            if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
                return res.status(400).json({success:false,message:"Usuário inválido"});
            }

            if (!/^\S+@\S+\.\S+$/.test(email)) {
                return res.status(400).json({success:false,message:"E-mail inválido"});
            }

            const exists = db.prepare(`
                SELECT id
                FROM resellers
                WHERE (LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?))
                  AND id <> ?
            `).get(username, email, id);

            if (exists) {
                return res.status(409).json({
                    success:false,
                    message:"Usuário ou e-mail já está em uso"
                });
            }

            const result = db.prepare(`
                UPDATE resellers
                SET username = ?, email = ?
                WHERE id = ?
            `).run(username, email, id);

            if (result.changes !== 1) {
                return res.status(404).json({success:false,message:"Revendedor não encontrado"});
            }

            return res.json({success:true,message:"Revendedor atualizado"});
        } catch (error) {
            console.error("Erro ao atualizar revendedor:", error);
            return res.status(500).json({success:false,message:"Erro interno ao atualizar revendedor"});
        }
    }
);

app.post(
    "/api/admin/resellers/balance",
    authRequired,
    masterOwnerRequired,
    (req, res) => {
        try {
            const id = Number(req.body.id);
            const operation = String(req.body.operation || "add").toLowerCase();
            const amount = Number(req.body.amount);

            if (!Number.isInteger(id) || id <= 0) {
                return res.status(400).json({success:false,message:"ID inválido"});
            }

            if (!Number.isFinite(amount) || amount < 0) {
                return res.status(400).json({success:false,message:"Valor inválido"});
            }

            const cents = Math.round(amount * 100);
            const reseller = db.prepare(`SELECT * FROM resellers WHERE id = ?`).get(id);

            if (!reseller) {
                return res.status(404).json({success:false,message:"Revendedor não encontrado"});
            }

            let newBalance = Number(reseller.balance_cents || 0);

            if (operation === "set") {
                newBalance = cents;
            } else if (operation === "subtract") {
                newBalance = Math.max(0, newBalance - cents);
            } else if (operation === "add") {
                newBalance += cents;
            } else {
                return res.status(400).json({success:false,message:"Operação de saldo inválida"});
            }

            db.prepare(`
                UPDATE resellers
                SET balance_cents = ?
                WHERE id = ?
            `).run(newBalance, id);

            return res.json({
                success:true,
                balance:newBalance / 100,
                message:"Saldo atualizado"
            });
        } catch (error) {
            console.error("Erro ao alterar saldo do revendedor:", error);
            return res.status(500).json({success:false,message:"Erro interno ao alterar saldo"});
        }
    }
);

app.post(
    "/api/admin/resellers/status",
    authRequired,
    masterOwnerRequired,
    (req, res) => {
        try {
            const id = Number(req.body.id);
            const enabled = req.body.enabled ? 1 : 0;

            const result = db.prepare(`
                UPDATE resellers
                SET enabled = ?
                WHERE id = ?
            `).run(enabled, id);

            if (result.changes !== 1) {
                return res.status(404).json({success:false,message:"Revendedor não encontrado"});
            }

            if (!enabled) {
                db.prepare(`DELETE FROM reseller_sessions WHERE reseller_id = ?`).run(id);
            }

            return res.json({success:true,message: enabled ? "Revendedor ativado" : "Revendedor desativado"});
        } catch (error) {
            console.error("Erro ao alterar status do revendedor:", error);
            return res.status(500).json({success:false,message:"Erro interno ao alterar status"});
        }
    }
);

app.post(
    "/api/admin/resellers/password",
    authRequired,
    masterOwnerRequired,
    (req, res) => {
        try {
            const id = Number(req.body.id);
            const password = String(req.body.password || "");

            if (password.length < 8) {
                return res.status(400).json({success:false,message:"A senha precisa ter pelo menos 8 caracteres"});
            }

            const {salt, hash} = hashPassword(password);
            const result = db.prepare(`
                UPDATE resellers
                SET password_hash = ?, password_salt = ?
                WHERE id = ?
            `).run(hash, salt, id);

            if (result.changes !== 1) {
                return res.status(404).json({success:false,message:"Revendedor não encontrado"});
            }

            db.prepare(`DELETE FROM reseller_sessions WHERE reseller_id = ?`).run(id);

            return res.json({success:true,message:"Senha alterada. Sessões antigas foram encerradas."});
        } catch (error) {
            console.error("Erro ao alterar senha do revendedor:", error);
            return res.status(500).json({success:false,message:"Erro interno ao alterar senha"});
        }
    }
);

app.delete(
    "/api/admin/resellers/delete",
    authRequired,
    masterOwnerRequired,
    (req, res) => {
        try {
            const id = Number(req.body.id);
            const result = db.prepare(`DELETE FROM resellers WHERE id = ?`).run(id);

            if (result.changes !== 1) {
                return res.status(404).json({success:false,message:"Revendedor não encontrado"});
            }

            return res.json({success:true,message:"Revendedor excluído"});
        } catch (error) {
            console.error("Erro ao excluir revendedor:", error);
            return res.status(500).json({success:false,message:"Erro interno ao excluir revendedor"});
        }
    }
);

app.post(
    "/api/reseller/auth/register",
    (req, res) => {
        try {
            const username =
                normalizeUsername(
                    req.body.username
                );

            const email =
                String(
                    req.body.email ||
                    ""
                )
                .trim()
                .toLowerCase();

            const password =
                String(
                    req.body.password ||
                    ""
                );

            if (
                !/^[a-z0-9_.-]{3,32}$/
                    .test(username)
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Nome de usuario invalido"
                });
            }

            if (
                !/^[^\s@]+@[^\s@]+\.[^\s@]+$/
                    .test(email)
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "E-mail invalido"
                });
            }

            if (password.length < 8) {
                return res.status(400).json({
                    success: false,
                    message:
                        "A senha precisa ter pelo menos 8 caracteres"
                });
            }

            const exists =
                db.prepare(`
                    SELECT id
                    FROM resellers
                    WHERE username = ?
                       OR email = ?
                `).get(
                    username,
                    email
                );

            if (exists) {
                return res.status(409).json({
                    success: false,
                    message:
                        "Usuario ou e-mail ja cadastrado"
                });
            }

            const {
                salt,
                hash
            } = hashPassword(
                password
            );

            const result =
                db.prepare(`
                    INSERT INTO resellers (
                        username,
                        email,
                        password_hash,
                        password_salt,
                        enabled,
                        balance_cents
                    )
                    VALUES (
                        ?, ?, ?, ?,
                        1,
                        0
                    )
                `).run(
                    username,
                    email,
                    hash,
                    salt
                );

            return res.status(201).json({
                success: true,
                message:
                    "Conta de revendedor criada",
                user: resellerPublic(
                    db.prepare(`
                        SELECT *
                        FROM resellers
                        WHERE id = ?
                    `).get(
                        result.lastInsertRowid
                    )
                )
            });

        } catch (error) {
            console.error(
                "Erro no cadastro de revendedor:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Erro interno ao criar conta"
            });
        }
    }
);

app.post(
    "/api/reseller/auth/login",
    (req, res) => {
        try {
            const username =
                normalizeUsername(
                    req.body.username
                );

            const password =
                String(
                    req.body.password ||
                    ""
                );

            const reseller =
                db.prepare(`
                    SELECT *
                    FROM resellers
                    WHERE username = ?
                `).get(
                    username
                );

            if (
                !reseller ||
                !reseller.enabled ||
                !verifyPassword(
                    password,
                    reseller.password_salt,
                    reseller.password_hash
                )
            ) {
                return res.status(401).json({
                    success: false,
                    message:
                        "Usuario ou senha invalidos"
                });
            }

            const loginAt =
                nowISO();

            db.prepare(`
                UPDATE resellers
                SET last_login_at = ?
                WHERE id = ?
            `).run(
                loginAt,
                reseller.id
            );

            const fresh =
                db.prepare(`
                    SELECT *
                    FROM resellers
                    WHERE id = ?
                `).get(
                    reseller.id
                );

            const session =
                createResellerSession(
                    reseller.id
                );

            return res.json({
                success: true,
                token:
                    session.token,
                expires_at:
                    session.expiresAt,
                user:
                    resellerPublic(
                        fresh
                    )
            });

        } catch (error) {
            console.error(
                "Erro no login de revendedor:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Erro interno no login"
            });
        }
    }
);

app.post(
    "/api/reseller/auth/logout",
    resellerAuthRequired,
    (req, res) => {
        db.prepare(`
            DELETE FROM reseller_sessions
            WHERE token_hash = ?
        `).run(
            hashToken(
                req.resellerToken
            )
        );

        return res.json({
            success: true
        });
    }
);

app.get(
    "/api/reseller/me",
    resellerAuthRequired,
    (req, res) => {
        const reseller =
            db.prepare(`
                SELECT *
                FROM resellers
                WHERE id = ?
            `).get(
                req.reseller.id
            );

        return res.json({
            success: true,
            user:
                resellerPublic(
                    reseller
                )
        });
    }
);

/* =========================================================
   REVENDEDOR - KEYS
========================================================= */

app.get(
    "/api/reseller/keys",
    resellerAuthRequired,
    (req, res) => {
        try {
            const rows =
                db.prepare(`
                    SELECT
                        keys.key,
                        keys.status,
                        keys.created_at,
                        keys.activated_at,
                        keys.expires_at,
                        keys.device_udid,
                        keys.last_reset_at,
                        reseller_keys.price_cents
                    FROM reseller_keys
                    JOIN keys
                        ON keys.id =
                           reseller_keys.key_id
                    WHERE reseller_keys.reseller_id = ?
                    ORDER BY reseller_keys.id DESC
                    LIMIT 500
                `).all(
                    req.reseller.id
                );

            const keys =
                rows.map(
                    row => ({
                        key:
                            row.key,
                        status:
                            checkKeyExpiration(
                                getKey(
                                    row.key
                                )
                            ),
                        days:
                            getDaysFromKey(
                                row
                            ),
                        price:
                            Number(
                                row.price_cents
                            ) / 100,
                        created_at:
                            row.created_at,
                        activated_at:
                            row.activated_at,
                        expires_at:
                            row.expires_at,
                        device_bound:
                            Boolean(
                                row.device_udid
                            )
                    })
                );

            return res.json({
                success: true,
                keys
            });

        } catch (error) {
            console.error(
                "Erro no historico do revendedor:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Erro interno ao listar keys"
            });
        }
    }
);

app.post(
    "/api/reseller/keys/check",
    resellerAuthRequired,
    (req, res) => {
        try {
            const key =
                String(
                    req.body.key ||
                    ""
                ).trim();

            if (!key) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Key nao informada"
                });
            }

            const row =
                db.prepare(`
                    SELECT
                        keys.*,
                        reseller_keys.price_cents
                    FROM reseller_keys
                    JOIN keys
                        ON keys.id =
                           reseller_keys.key_id
                    WHERE reseller_keys.reseller_id = ?
                      AND keys.key = ?
                `).get(
                    req.reseller.id,
                    key
                );

            if (!row) {
                return res.json({
                    success: true,
                    found: false
                });
            }

            const status =
                checkKeyExpiration(
                    row
                );

            return res.json({
                success: true,
                found: true,
                key:
                    row.key,
                status,
                days:
                    getDaysFromKey(
                        row
                    ),
                price:
                    Number(
                        row.price_cents
                    ) / 100,
                created_at:
                    row.created_at,
                activated_at:
                    row.activated_at,
                expires_at:
                    row.expires_at,
                device_bound:
                    Boolean(
                        row.device_udid
                    )
            });

        } catch (error) {
            console.error(
                "Erro no check do revendedor:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Erro interno ao consultar key"
            });
        }
    }
);

app.post(
    "/api/reseller/keys/generate",
    resellerAuthRequired,
    (req, res) => {
        try {
            const plan =
                String(
                    req.body.plan ||
                    ""
                );

            const planData =
                RESELLER_PLANS[
                    plan
                ];

            if (!planData) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Plano invalido"
                });
            }

            const generate =
                db.transaction(() => {
                    const reseller =
                        db.prepare(`
                            SELECT *
                            FROM resellers
                            WHERE id = ?
                        `).get(
                            req.reseller.id
                        );

                    if (
                        !reseller ||
                        !reseller.enabled
                    ) {
                        const error =
                            new Error(
                                "Conta desativada"
                            );

                        error.code =
                            "RESELLER_DISABLED";

                        throw error;
                    }

                    if (
                        Number(
                            reseller.balance_cents ||
                            0
                        ) <
                        planData.priceCents
                    ) {
                        const error =
                            new Error(
                                "Saldo insuficiente"
                            );

                        error.code =
                            "INSUFFICIENT_BALANCE";

                        throw error;
                    }

                    let key;

                    do {
                        key =
                            generateKeyValue(
                                "EXTERNAL"
                            );
                    } while (
                        db.prepare(`
                            SELECT id
                            FROM keys
                            WHERE key = ?
                        `).get(
                            key
                        )
                    );

                    const insertKey =
                        db.prepare(`
                            INSERT INTO keys (
                                key,
                                prefix,
                                status,
                                expires_at,
                                last_reset_at,
                                activated_at,
                                paused_at,
                                remaining_ms,
                                device_udid,
                                device_bound_at,
                                device_reset_at,
                                created_by_user_id
                            )
                            VALUES (
                                ?,
                                'EXTERNAL',
                                'unused',
                                NULL,
                                ?,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL
                            )
                        `).run(
                            key,
                            `PLAN:${planData.days}`
                        );

                    db.prepare(`
                        INSERT INTO reseller_keys (
                            reseller_id,
                            key_id,
                            price_cents
                        )
                        VALUES (?, ?, ?)
                    `).run(
                        reseller.id,
                        insertKey.lastInsertRowid,
                        planData.priceCents
                    );

                    const debit =
                        db.prepare(`
                            UPDATE resellers
                            SET balance_cents =
                                balance_cents - ?
                            WHERE id = ?
                              AND balance_cents >= ?
                        `).run(
                            planData.priceCents,
                            reseller.id,
                            planData.priceCents
                        );

                    if (
                        debit.changes !==
                        1
                    ) {
                        throw new Error(
                            "Saldo insuficiente"
                        );
                    }

                    return {
                        key,
                        balanceCents:
                            Number(
                                reseller.balance_cents
                            ) -
                            planData.priceCents
                    };
                });

            const result =
                generate();

            return res.json({
                success: true,
                key:
                    result.key,
                plan,
                days:
                    planData.days,
                charged:
                    planData.priceCents /
                    100,
                balance:
                    result.balanceCents /
                    100
            });

        } catch (error) {
            if (
                error &&
                error.code ===
                "INSUFFICIENT_BALANCE"
            ) {
                return res.status(402).json({
                    success: false,
                    code:
                        "INSUFFICIENT_BALANCE",
                    message:
                        "Saldo insuficiente para gerar esta key"
                });
            }

            console.error(
                "Erro ao gerar key do revendedor:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    error.message ||
                    "Erro interno ao gerar key"
            });
        }
    }
);

app.get(
    "/api/reseller/mercadopago/status",
    resellerAuthRequired,
    async (req, res) => {
        try {
            const methods =
                await mercadoPagoRequest(
                    "/v1/payment_methods",
                    { method: "GET" }
                );

            return res.json({
                success: true,
                configured: true,
                pix_available:
                    Array.isArray(methods)
                        ? methods.some(
                            item =>
                                String(
                                    item.id ||
                                    ""
                                ).toLowerCase() === "pix"
                          )
                        : true
            });

        } catch (error) {
            console.error(
                "Teste Mercado Pago:",
                error.details ||
                error
            );

            return res.status(
                Number(error.status) || 500
            ).json({
                success: false,
                configured: false,
                message:
                    error.message ||
                    "Falha ao autenticar Mercado Pago"
            });
        }
    }
);

/* =========================================================
   REVENDEDOR - DEPOSITO PIX
========================================================= */

app.post(
    "/api/reseller/deposits/pix",
    resellerAuthRequired,
    async (req, res) => {
        try {
            const amount =
                Number(
                    req.body.amount
                );

            const amountCents =
                Math.round(
                    amount *
                    100
                );

            if (
                !Number.isFinite(
                    amount
                ) ||
                amountCents <
                RESELLER_MIN_DEPOSIT_CENTS
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "O deposito minimo e R$ 25,00"
                });
            }

            if (
                amountCents >
                100000000
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Valor de deposito invalido"
                });
            }

            const reseller =
                db.prepare(`
                    SELECT *
                    FROM resellers
                    WHERE id = ?
                `).get(
                    req.reseller.id
                );

            const idempotencyKey =
                crypto.randomUUID();

            const insertDeposit =
                db.prepare(`
                    INSERT INTO reseller_deposits (
                        reseller_id,
                        amount_cents,
                        status,
                        credited,
                        idempotency_key
                    )
                    VALUES (
                        ?,
                        ?,
                        'pending',
                        0,
                        ?
                    )
                `).run(
                    reseller.id,
                    amountCents,
                    idempotencyKey
                );

            try {
                const payment =
                    await mercadoPagoRequest(
                        "/v1/payments",
                        {
                            method:
                                "POST",
                            headers: {
                                "Content-Type":
                                    "application/json",
                                "X-Idempotency-Key":
                                    idempotencyKey
                            },
                            body:
                                JSON.stringify({
                                    transaction_amount:
                                        amountCents /
                                        100,
                                    description:
                                        "Deposito revendedor EXTERNAL IOS",
                                    payment_method_id:
                                        "pix",
                                    payer: {
                                        email:
                                            reseller.email
                                    },
                                    external_reference:
                                        "reseller_deposit_" +
                                        insertDeposit.lastInsertRowid,
                                    notification_url:
                                        PUBLIC_URL +
                                        "/api/mercadopago/webhook"
                                })
                        }
                    );

                db.prepare(`
                    UPDATE reseller_deposits
                    SET
                        payment_id = ?,
                        status = ?
                    WHERE id = ?
                `).run(
                    String(
                        payment.id
                    ),
                    String(
                        payment.status ||
                        "pending"
                    ),
                    insertDeposit.lastInsertRowid
                );

                const tx =
                    payment
                        .point_of_interaction
                        ?.transaction_data ||
                    {};

                return res.json({
                    success: true,
                    payment_id:
                        String(
                            payment.id
                        ),
                    status:
                        payment.status ||
                        "pending",
                    qr_code:
                        tx.qr_code ||
                        "",
                    qr_code_base64:
                        tx.qr_code_base64 ||
                        "",
                    ticket_url:
                        tx.ticket_url ||
                        ""
                });

            } catch (error) {
                db.prepare(`
                    UPDATE reseller_deposits
                    SET status = 'error'
                    WHERE id = ?
                `).run(
                    insertDeposit.lastInsertRowid
                );

                throw error;
            }

        } catch (error) {
            console.error(
                "Erro ao criar PIX:",
                error.details ||
                error
            );

            if (
                error &&
                error.code ===
                "MERCADO_PAGO_NOT_CONFIGURED"
            ) {
                return res.status(503).json({
                    success: false,
                    code:
                        "MERCADO_PAGO_NOT_CONFIGURED",
                    message:
                        "Access Token do Mercado Pago ainda nao foi colocado no server.js"
                });
            }

            return res.status(
                Number(
                    error.status
                ) >= 400 &&
                Number(
                    error.status
                ) < 600
                    ? Number(
                        error.status
                    )
                    : 500
            ).json({
                success: false,
                message:
                    error.message ||
                    "Erro ao gerar PIX"
            });
        }
    }
);

app.get(
    "/api/reseller/deposits/:paymentId/status",
    resellerAuthRequired,
    async (req, res) => {
        try {
            const paymentId =
                String(
                    req.params.paymentId ||
                    ""
                );

            const deposit =
                db.prepare(`
                    SELECT *
                    FROM reseller_deposits
                    WHERE payment_id = ?
                      AND reseller_id = ?
                `).get(
                    paymentId,
                    req.reseller.id
                );

            if (!deposit) {
                return res.status(404).json({
                    success: false,
                    message:
                        "Deposito nao encontrado"
                });
            }

            const {
                payment,
                reseller
            } =
                await syncMercadoPagoPayment(
                    paymentId
                );

            return res.json({
                success: true,
                payment_id:
                    String(
                        payment.id
                    ),
                status:
                    payment.status ||
                    deposit.status,
                balance:
                    reseller
                        ? Number(
                            reseller.balance_cents ||
                            0
                        ) / 100
                        : Number(
                            req.reseller.balance_cents ||
                            0
                        ) / 100
            });

        } catch (error) {
            console.error(
                "Erro ao consultar PIX:",
                error.details ||
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    error.message ||
                    "Erro ao consultar pagamento"
            });
        }
    }
);

/* =========================================================
   MERCADO PAGO - WEBHOOK
========================================================= */

app.post(
    "/api/mercadopago/webhook",
    async (req, res) => {
        res.status(200).json({
            received: true
        });

        try {
            const paymentId =
                String(
                    req.body?.data?.id ||
                    req.query?.["data.id"] ||
                    req.query?.id ||
                    ""
                ).trim();

            if (!paymentId) {
                return;
            }

            const exists =
                db.prepare(`
                    SELECT id
                    FROM reseller_deposits
                    WHERE payment_id = ?
                `).get(
                    paymentId
                );

            if (!exists) {
                return;
            }

            await syncMercadoPagoPayment(
                paymentId
            );

        } catch (error) {
            console.error(
                "Erro no webhook Mercado Pago:",
                error.details ||
                error
            );
        }
    }
);


/* =========================================================
   AUDITORIA - OWNER
========================================================= */

app.get(
    "/api/admin/audit",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const logs = db.prepare(`
                SELECT
                    audit_logs.id,
                    audit_logs.action,
                    audit_logs.target_type,
                    audit_logs.target_id,
                    audit_logs.created_at,
                    users.username
                FROM audit_logs
                LEFT JOIN users
                    ON users.id =
                       audit_logs.user_id
                ORDER BY audit_logs.id DESC
                LIMIT 500
            `).all();

            res.json({
                success: true,
                logs
            });

        } catch (error) {
            console.error("Erro ao listar auditoria:", error);

            res.status(500).json({
                success: false,
                message:
                    "Erro interno ao listar auditoria"
            });
        }
    }
);

/* =========================================================
   404 / ERRO
========================================================= */

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "Rota não encontrada"
    });
});

app.use((error, req, res, next) => {
    console.error("Erro global:", error);

    res.status(500).json({
        success: false,
        message: "Erro interno do servidor"
    });
});

/* =========================================================
   START
========================================================= */

app.listen(PORT, HOST, () => {
    console.log("=================================");
    console.log(`Servidor: http://${HOST}:${PORT}`);
    console.log(`API pública: ${PUBLIC_URL}`);
    console.log(`Painel: ${PUBLIC_URL}/`);
    console.log(`Health: ${PUBLIC_URL}/health`);
    console.log("Prefixo padrão: EXTERNAL");
    console.log(`Máximo por geração: ${MAX_KEYS_PER_REQUEST}`);
    console.log("Master owner: nextaway");
    console.log("=================================");
});