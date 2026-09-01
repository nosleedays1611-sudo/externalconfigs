const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const path = require("path");
const forge = require("node-forge");
const db = require("./database");

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
    let owner = db.getUserByUsername(MASTER_OWNER);

    if (owner) {
        refreshAccountStatus(owner);
        return;
    }

    const password = String(
        process.env.NEXTAWAY_PASSWORD || ""
    );

    if (password.length < 8) {
        console.warn(
            "ATENÇÃO: defina NEXTAWAY_PASSWORD com pelo menos 8 caracteres."
        );
        return;
    }

    const { salt, hash } = hashPassword(password);

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

    console.log('Conta master owner "nextaway" criada.');
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

app.post("/api/keys/check", (req, res) => {
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
            return res.json({
                success: true,
                found: false,
                message: "Key não encontrada"
            });
        }

        res.json({
            success: true,
            found: true,

            key: keyData.key,
            prefix: keyData.prefix,
            status:
                checkKeyExpiration(keyData),
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
            device_bound_at:
                keyData.device_bound_at
        });

    } catch (error) {
        console.error("Erro ao verificar key:", error);

        res.status(500).json({
            success: false,
            message: "Erro interno ao verificar key"
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
   RESET KEY
========================================================= */

app.post(
    "/api/keys/reset",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(req.body.key || "").trim();

            const keyData = getKey(key);

            if (!keyData) {
                return res.status(404).json({
                    success: false,
                    message: "Key não encontrada"
                });
            }

            db.prepare(`
                UPDATE keys
                SET
                    status = 'unused',
                    activated_at = NULL,
                    expires_at = NULL,
                    paused_at = NULL,
                    remaining_ms = NULL
                WHERE id = ?
            `).run(keyData.id);

            logAction(
                req.user.id,
                "reset_key",
                "key",
                keyData.key
            );

            res.json({
                success: true,
                message: "Key resetada com sucesso",
                key: keyData.key,
                status: "unused",
                days:
                    getDaysFromKey(keyData),
                device_bound:
                    Boolean(keyData.device_udid)
            });

        } catch (error) {
            console.error("Erro ao resetar key:", error);

            res.status(500).json({
                success: false,
                message:
                    "Erro interno ao resetar key"
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

            const keyData = getKey(key);

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

            const keyData = getKey(key);

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

            const keyData = getKey(key);

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
   DELETAR KEY
========================================================= */

app.delete(
    "/api/keys/delete",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(req.body.key || "").trim();

            const keyData = getKey(key);

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
            const rows = db.prepare(`
                SELECT
                    keys.*,
                    users.username AS created_by_username
                FROM keys
                LEFT JOIN users
                    ON users.id =
                       keys.created_by_user_id
                ORDER BY keys.id DESC
            `).all();

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
        .replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&");

    const pattern = new RegExp(
        "<key>\\\\s*" +
        escapedKey +
        "\\\\s*</key>\\\\s*<string>([\\\\s\\\\S]*?)</string>",
        "i"
    );

    const match = String(xml || "").match(pattern);

    return match
        ? decodeProfileXmlEntity(match[1]).trim()
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

        const encodings = ["utf8", "latin1"];

        for (const encoding of encodings) {
            const raw = buffer.toString(encoding);

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
                extractProfileString(
                    xml,
                    "UDID"
                ),
            PRODUCT:
                extractProfileString(
                    xml,
                    "PRODUCT"
                ),
            VERSION:
                extractProfileString(
                    xml,
                    "VERSION"
                ),
            SERIAL:
                extractProfileString(
                    xml,
                    "SERIAL"
                ),
            IMEI:
                extractProfileString(
                    xml,
                    "IMEI"
                ),
            ICCID:
                extractProfileString(
                    xml,
                    "ICCID"
                )
        };
    }

    /*
     * Primeiro tenta plist em claro. Isso mantém
     * compatibilidade caso algum iOS/proxy entregue
     * o XML sem envelope PKCS#7.
     */
    const directXml =
        findPlistInBuffer(body);

    if (directXml) {
        return deviceFromXml(directXml);
    }

    const normalizedType =
        String(contentType || "")
            .toLowerCase();

    if (
        !normalizedType.includes(
            "application/pkcs7-signature"
        ) &&
        !normalizedType.includes(
            "application/pkcs7-mime"
        )
    ) {
        return null;
    }

    try {
        /*
         * O retorno do Profile Service chega como CMS/PKCS#7.
         * Parseamos o DER e percorremos os OCTET STRINGs
         * internos até localizar o plist encapsulado.
         */
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

        let xml = null;

        function walk(node) {
            if (xml || !node) {
                return;
            }

            if (Array.isArray(node.value)) {
                for (const child of node.value) {
                    walk(child);

                    if (xml) {
                        return;
                    }
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

                const found =
                    findPlistInBuffer(
                        candidate
                    );

                if (found) {
                    xml = found;
                }
            }
        }

        walk(root);

        /*
         * Fallback pelo objeto PKCS#7 do node-forge.
         * Algumas mensagens SignedData expõem o conteúdo
         * diretamente em message.content.
         */
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
                    "Fallback PKCS#7 não conseguiu ler SignedData:",
                    pkcs7Error.message
                );
            }
        }

        if (!xml) {
            console.error(
                "PKCS#7 recebido, mas nenhum plist XML foi localizado."
            );

            return null;
        }

        return deviceFromXml(xml);

    } catch (error) {
        console.error(
            "Falha decodificando PKCS#7:",
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