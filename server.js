const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const path = require("path");
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
