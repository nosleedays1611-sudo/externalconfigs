const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const path = require("path");
const db = require("./database");

const app = express();

/*
==================================================
CONFIG
==================================================
*/

const PORT = Number(process.env.PORT) || 80;
const HOST = "0.0.0.0";

const PUBLIC_URL =
    process.env.PUBLIC_URL ||
    "https://externalconfig.shardweb.app";

const MASTER_OWNER = "nextaway";

const SESSION_HOURS = 24;

const MAX_KEYS_PER_REQUEST = 100;

/*
==================================================
MIDDLEWARE
==================================================
*/

app.use(cors({
    origin: true,

    methods: [
        "GET",
        "POST",
        "DELETE",
        "OPTIONS"
    ],

    allowedHeaders: [
        "Content-Type",
        "Authorization"
    ]
}));

app.use(express.json({
    limit: "64kb"
}));

/*
==================================================
FRONTEND
==================================================
*/

app.use(
    express.static(
        path.join(
            __dirname,
            "site"
        )
    )
);

app.get("/", (req, res) => {
    return res.sendFile(
        path.join(
            __dirname,
            "site",
            "index.html"
        )
    );
});

/*
==================================================
HEALTH
==================================================
*/

app.get("/health", (req, res) => {
    return res.json({
        ok: true,
        message: "API funcionando",
        url: PUBLIC_URL
    });
});

/*
==================================================
FUNÇÕES GERAIS
==================================================
*/

function nowISO() {
    return new Date().toISOString();
}

function normalizeUsername(
    username
) {
    return String(
        username || ""
    )
        .trim()
        .toLowerCase();
}

function normalizeUDID(
    udid
) {
    return String(
        udid || ""
    )
        .trim()
        .replace(
            /\s+/g,
            ""
        )
        .toUpperCase();
}

function validUDID(
    udid
) {
    return /^[A-Z0-9-]{8,128}$/.test(
        udid
    );
}

/*
==================================================
PREFIXO / KEYS
==================================================
*/

function sanitizePrefix(
    prefix
) {
    prefix = String(
        prefix || "EXTERNAL"
    )
        .trim()
        .toUpperCase()
        .replace(
            /[^A-Z0-9_-]/g,
            ""
        );

    return prefix || "EXTERNAL";
}

function generateRandomCode(
    length = 5
) {
    const chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let result = "";

    for (
        let i = 0;
        i < length;
        i++
    ) {
        result +=
            chars[
                crypto.randomInt(
                    0,
                    chars.length
                )
            ];
    }

    return result;
}

function generateKey(
    prefix = "EXTERNAL"
) {
    prefix =
        sanitizePrefix(
            prefix
        );

    return (
        `${prefix}-IOS-` +
        generateRandomCode(5)
    );
}

/*
==================================================
TEMPO
==================================================
*/

function calculateExpiration(
    days,
    startTime = Date.now()
) {
    return new Date(
        startTime +
        Number(days) *
        24 *
        60 *
        60 *
        1000
    ).toISOString();
}

function getDaysFromKey(
    keyData
) {
    const value =
        String(
            keyData.last_reset_at ||
            ""
        );

    if (
        value.startsWith(
            "PLAN:"
        )
    ) {
        const days =
            Number(
                value.replace(
                    "PLAN:",
                    ""
                )
            );

        if (
            Number.isFinite(
                days
            )
        ) {
            return days;
        }
    }

    return null;
}

/*
==================================================
KEY DATABASE
==================================================
*/

function getKey(
    key
) {
    return db
        .prepare(`
            SELECT *
            FROM keys
            WHERE key = ?
        `)
        .get(
            String(
                key || ""
            ).trim()
        );
}

function checkKeyExpiration(
    keyData
) {
    if (
        keyData.status ===
            "active" &&
        keyData.expires_at &&
        new Date(
            keyData.expires_at
        ).getTime() <=
            Date.now()
    ) {
        db.prepare(`
            UPDATE keys
            SET status = 'expired'
            WHERE id = ?
        `).run(
            keyData.id
        );

        return "expired";
    }

    return keyData.status;
}

/*
==================================================
PASSWORD
==================================================
*/

function hashPassword(
    password,
    salt =
        crypto
            .randomBytes(16)
            .toString("hex")
) {
    const hash =
        crypto
            .scryptSync(
                String(password),
                salt,
                64
            )
            .toString("hex");

    return {
        salt,
        hash
    };
}

function verifyPassword(
    password,
    salt,
    expectedHash
) {
    try {
        const actual =
            crypto.scryptSync(
                String(password),
                salt,
                64
            );

        const expected =
            Buffer.from(
                expectedHash,
                "hex"
            );

        if (
            actual.length !==
            expected.length
        ) {
            return false;
        }

        return crypto
            .timingSafeEqual(
                actual,
                expected
            );

    } catch {
        return false;
    }
}

/*
==================================================
TOKEN / SESSÃO
==================================================
*/

function hashToken(
    token
) {
    return crypto
        .createHash(
            "sha256"
        )
        .update(
            String(token)
        )
        .digest(
            "hex"
        );
}

function createSession(
    userId
) {
    const token =
        crypto
            .randomBytes(32)
            .toString("hex");

    const tokenHash =
        hashToken(
            token
        );

    const expiresAt =
        new Date(
            Date.now() +
            SESSION_HOURS *
            60 *
            60 *
            1000
        ).toISOString();

    db.prepare(`
        INSERT INTO sessions (
            token_hash,
            user_id,
            expires_at
        )
        VALUES (?, ?, ?)
    `).run(
        tokenHash,
        userId,
        expiresAt
    );

    return {
        token,
        expiresAt
    };
}

function getBearerToken(
    req
) {
    const auth =
        String(
            req.headers
                .authorization ||
            ""
        );

    if (
        !auth.startsWith(
            "Bearer "
        )
    ) {
        return null;
    }

    return auth
        .slice(7)
        .trim();
}

/*
==================================================
AUDITORIA
==================================================
*/

function logAction(
    userId,
    action,
    targetType = null,
    targetId = null
) {
    try {
        db.logAction(
            userId,
            action,
            targetType,
            targetId
        );

    } catch (error) {
        console.error(
            "Falha ao registrar auditoria:",
            error.message
        );
    }
}

/*
==================================================
PLANO DA CONTA
==================================================
*/

function parseAccountPlan(
    body
) {
    const plan =
        String(
            body.account_plan ||
            body.plan ||
            "lifetime"
        )
            .trim()
            .toLowerCase();

    const plans = {
        "1d": 1,
        "7d": 7,
        "30d": 30
    };

    if (
        Object.prototype
            .hasOwnProperty
            .call(
                plans,
                plan
            )
    ) {
        return {
            plan,
            durationDays:
                plans[plan]
        };
    }

    if (
        plan ===
        "lifetime"
    ) {
        return {
            plan:
                "lifetime",

            durationDays:
                null
        };
    }

    if (
        plan ===
        "custom"
    ) {
        const days =
            Number(
                body.duration_days ??
                body.days
            );

        if (
            !Number.isInteger(
                days
            ) ||
            days <= 0 ||
            days > 36500
        ) {
            throw new Error(
                "Duração personalizada inválida"
            );
        }

        return {
            plan:
                "custom",

            durationDays:
                days
        };
    }

    throw new Error(
        "Plano da conta inválido"
    );
}

/*
==================================================
LIMITE DE KEYS
==================================================
*/

function parseKeyLimit(
    value
) {
    if (
        value === null ||
        value === undefined ||
        value === "" ||
        String(value)
            .toLowerCase() ===
            "unlimited"
    ) {
        return null;
    }

    const limit =
        Number(
            value
        );

    if (
        !Number.isInteger(
            limit
        ) ||
        limit < 0 ||
        limit > 10000000
    ) {
        throw new Error(
            "Limite de keys inválido"
        );
    }

    return limit;
}

/*
==================================================
STATUS / EXPIRAÇÃO DA CONTA
==================================================
*/

function refreshAccountStatus(
    user
) {
    if (!user) {
        return null;
    }

    /*
    MASTER OWNER
    */

    if (
        normalizeUsername(
            user.username
        ) ===
        MASTER_OWNER
    ) {
        if (
            user.role !==
                "owner" ||
            !user.enabled ||
            user.account_status !==
                "active" ||
            user.account_plan !==
                "lifetime" ||
            user.expires_at !==
                null ||
            user.key_limit !==
                null
        ) {
            db.prepare(`
                UPDATE users
                SET
                    role = 'owner',
                    enabled = 1,

                    account_status =
                        'active',

                    account_plan =
                        'lifetime',

                    duration_days =
                        NULL,

                    activated_at =
                        COALESCE(
                            activated_at,
                            created_at
                        ),

                    expires_at =
                        NULL,

                    key_limit =
                        NULL

                WHERE id = ?
            `).run(
                user.id
            );

            return db
                .getUserById(
                    user.id
                );
        }

        return user;
    }

    /*
    EXPIRAÇÃO NORMAL
    */

    if (
        user.account_status ===
            "active" &&
        user.account_plan !==
            "lifetime" &&
        user.expires_at &&
        new Date(
            user.expires_at
        ).getTime() <=
            Date.now()
    ) {
        db.prepare(`
            UPDATE users
            SET account_status =
                'expired'
            WHERE id = ?
        `).run(
            user.id
        );

        db.prepare(`
            DELETE
            FROM sessions
            WHERE user_id = ?
        `).run(
            user.id
        );

        return db
            .getUserById(
                user.id
            );
    }

    return user;
}

/*
==================================================
ATIVAR CONTA NO PRIMEIRO LOGIN
==================================================
*/

function activateAccountOnFirstLogin(
    user
) {
    user =
        refreshAccountStatus(
            user
        );

    if (!user) {
        return null;
    }

    if (
        normalizeUsername(
            user.username
        ) ===
        MASTER_OWNER
    ) {
        return user;
    }

    if (
        user.account_status !==
        "unused"
    ) {
        return user;
    }

    const activatedAt =
        nowISO();

    let expiresAt =
        null;

    if (
        user.account_plan !==
        "lifetime"
    ) {
        expiresAt =
            calculateExpiration(
                user.duration_days
            );
    }

    db.prepare(`
        UPDATE users
        SET
            account_status =
                'active',

            activated_at = ?,

            expires_at = ?

        WHERE id = ?
    `).run(
        activatedAt,
        expiresAt,
        user.id
    );

    return db
        .getUserById(
            user.id
        );
}

/*
==================================================
DADOS PÚBLICOS DA CONTA
==================================================
*/

function accountPublic(
    user
) {
    user =
        refreshAccountStatus(
            user
        );

    if (!user) {
        return null;
    }

    const generated =
        Number(
            user.keys_generated ||
            0
        );

    const limit =
        user.key_limit ===
            null ||
        user.key_limit ===
            undefined
            ? null
            : Number(
                user.key_limit
            );

    return {
        id:
            user.id,

        username:
            user.username,

        role:
            user.role,

        enabled:
            Boolean(
                user.enabled
            ),

        account_status:
            user.account_status,

        account_plan:
            user.account_plan,

        duration_days:
            user.duration_days,

        activated_at:
            user.activated_at,

        expires_at:
            user.expires_at,

        key_limit:
            limit,

        keys_generated:
            generated,

        keys_remaining:
            limit === null
                ? null
                : Math.max(
                    0,
                    limit -
                    generated
                ),

        unlimited_keys:
            limit === null,

        created_at:
            user.created_at,

        created_by:
            user.created_by,

        last_login_at:
            user.last_login_at,

        master_owner:
            normalizeUsername(
                user.username
            ) ===
            MASTER_OWNER
    };
}

/*
==================================================
VERIFICAR PERMISSÃO SOBRE KEY
==================================================
*/

function canManageKey(
    user,
    keyData
) {
    if (
        !user ||
        !keyData
    ) {
        return false;
    }

    /*
    OWNER GERENCIA TODAS
    */

    if (
        user.role ===
        "owner"
    ) {
        return true;
    }

    /*
    USER SOMENTE AS PRÓPRIAS
    */

    return (
        Number(
            keyData
                .created_by_user_id
        ) ===
        Number(
            user.id
        )
    );
}

function requireKeyPermission(
    req,
    res,
    keyData
) {
    if (
        !canManageKey(
            req.user,
            keyData
        )
    ) {
        res
            .status(403)
            .json({
                success: false,

                message:
                    "Você não possui permissão para gerenciar esta key"
            });

        return false;
    }

    return true;
}

/*
==================================================
MASTER OWNER
==================================================
*/

function ensureMasterOwner() {
    const existing =
        db.getUserByUsername(
            MASTER_OWNER
        );

    if (existing) {
        refreshAccountStatus(
            existing
        );

        return;
    }

    const password =
        String(
            process.env
                .NEXTAWAY_PASSWORD ||
            ""
        );

    if (
        password.length < 8
    ) {
        console.warn(
            "ATENÇÃO: conta nextaway ainda não existe."
        );

        console.warn(
            "Defina NEXTAWAY_PASSWORD no servidor com pelo menos 8 caracteres."
        );

        return;
    }

    const {
        salt,
        hash
    } = hashPassword(
        password
    );

    const activatedAt =
        nowISO();

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
            ?,
            ?,
            ?,

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
        activatedAt
    );

    console.log(
        'Conta master owner "nextaway" criada.'
    );
}

ensureMasterOwner();

/*
==================================================
AUTH MIDDLEWARE
==================================================
*/

function authRequired(
    req,
    res,
    next
) {
    try {
        const token =
            getBearerToken(
                req
            );

        if (!token) {
            return res
                .status(401)
                .json({
                    success: false,
                    message:
                        "Não autenticado"
                });
        }

        const session =
            db.prepare(`
                SELECT

                    sessions.id
                        AS session_id,

                    sessions.expires_at
                        AS session_expires_at,

                    users.*

                FROM sessions

                JOIN users
                    ON users.id =
                       sessions.user_id

                WHERE
                    sessions.token_hash = ?
            `).get(
                hashToken(
                    token
                )
            );

        if (!session) {
            return res
                .status(401)
                .json({
                    success: false,
                    message:
                        "Sessão inválida"
                });
        }

        if (
            new Date(
                session
                    .session_expires_at
            ).getTime() <=
            Date.now()
        ) {
            db.prepare(`
                DELETE
                FROM sessions
                WHERE id = ?
            `).run(
                session
                    .session_id
            );

            return res
                .status(401)
                .json({
                    success: false,
                    message:
                        "Sessão expirada"
                });
        }

        let user =
            refreshAccountStatus(
                session
            );

        if (
            !user.enabled
        ) {
            db.prepare(`
                DELETE
                FROM sessions
                WHERE user_id = ?
            `).run(
                user.id
            );

            return res
                .status(401)
                .json({
                    success: false,
                    message:
                        "Conta desativada"
                });
        }

        if (
            user.account_status ===
            "expired"
        ) {
            db.prepare(`
                DELETE
                FROM sessions
                WHERE user_id = ?
            `).run(
                user.id
            );

            return res
                .status(401)
                .json({
                    success: false,

                    code:
                        "ACCOUNT_EXPIRED",

                    message:
                        "Conta expirada"
                });
        }

        req.user =
            user;

        req.sessionToken =
            token;

        return next();

    } catch (error) {
        return next(
            error
        );
    }
}

function ownerRequired(
    req,
    res,
    next
) {
    if (
        !req.user ||
        req.user.role !==
            "owner"
    ) {
        return res
            .status(403)
            .json({
                success: false,

                message:
                    "Acesso permitido somente ao owner"
            });
    }

    return next();
}

/*
==================================================
LOGIN
==================================================
*/

app.post(
    "/api/auth/login",
    (req, res) => {
        try {
            const username =
                normalizeUsername(
                    req.body
                        .username
                );

            const password =
                String(
                    req.body
                        .password ||
                    ""
                );

            if (
                !username ||
                !password
            ) {
                return res
                    .status(400)
                    .json({
                        success:
                            false,

                        message:
                            "Usuário e senha são obrigatórios"
                    });
            }

            let user =
                db.getUserByUsername(
                    username
                );

            if (
                !user ||
                !user.enabled ||
                !verifyPassword(
                    password,
                    user
                        .password_salt,
                    user
                        .password_hash
                )
            ) {
                return res
                    .status(401)
                    .json({
                        success:
                            false,

                        message:
                            "Usuário ou senha inválidos"
                    });
            }

            user =
                refreshAccountStatus(
                    user
                );

            if (
                user
                    .account_status ===
                "expired"
            ) {
                return res
                    .status(403)
                    .json({
                        success:
                            false,

                        code:
                            "ACCOUNT_EXPIRED",

                        message:
                            "Esta conta expirou"
                    });
            }

            user =
                activateAccountOnFirstLogin(
                    user
                );

            const loginAt =
                nowISO();

            db.prepare(`
                UPDATE users
                SET last_login_at = ?
                WHERE id = ?
            `).run(
                loginAt,
                user.id
            );

            user =
                db.getUserById(
                    user.id
                );

            const session =
                createSession(
                    user.id
                );

            logAction(
                user.id,
                "login",
                "user",
                String(
                    user.id
                )
            );

            return res.json({
                success:
                    true,

                token:
                    session.token,

                expires_at:
                    session
                        .expiresAt,

                user:
                    accountPublic(
                        user
                    )
            });

        } catch (error) {
            console.error(
                "Erro no login:",
                error
            );

            return res
                .status(500)
                .json({
                    success:
                        false,

                    message:
                        "Erro interno no login"
                });
        }
    }
);

/*
==================================================
AUTH ME
==================================================
*/

app.get(
    "/api/auth/me",
    authRequired,
    (req, res) => {
        return res.json({
            success: true,

            user:
                accountPublic(
                    req.user
                )
        });
    }
);

/*
==================================================
LOGOUT
==================================================
*/

app.post(
    "/api/auth/logout",
    authRequired,
    (req, res) => {
        db.prepare(`
            DELETE
            FROM sessions
            WHERE token_hash = ?
        `).run(
            hashToken(
                req.sessionToken
            )
        );

        return res.json({
            success: true,

            message:
                "Logout realizado"
        });
    }
);
/*
==================================================
OWNER - LISTAR USUÁRIOS
==================================================
*/

app.get(
    "/api/admin/users",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const rows =
                db.prepare(`
                    SELECT *
                    FROM users
                    ORDER BY id DESC
                `).all();

            const users =
                rows.map(
                    accountPublic
                );

            return res.json({
                success: true,
                total:
                    users.length,
                users
            });

        } catch (error) {
            console.error(
                "Erro ao listar usuários:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao listar usuários"
                });
        }
    }
);

/*
==================================================
OWNER - CRIAR USUÁRIO
==================================================
*/

app.post(
    "/api/admin/users/create",
    authRequired,
    ownerRequired,
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

            const role =
                String(
                    req.body.role ||
                    "user"
                )
                    .trim()
                    .toLowerCase();

            if (
                !/^[a-z0-9_.-]{3,32}$/.test(
                    username
                )
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Nome de usuário inválido"
                    });
            }

            if (
                password.length < 8
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "A senha precisa ter pelo menos 8 caracteres"
                    });
            }

            if (
                ![
                    "owner",
                    "user"
                ].includes(
                    role
                )
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Cargo inválido. Use owner ou user."
                    });
            }

            if (
                username ===
                MASTER_OWNER
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Nome de usuário reservado"
                    });
            }

            const exists =
                db.getUserByUsername(
                    username
                );

            if (exists) {
                return res
                    .status(409)
                    .json({
                        success: false,
                        message:
                            "Usuário já existe"
                    });
            }

            let accountPlan;
            let keyLimit;

            try {
                accountPlan =
                    parseAccountPlan(
                        req.body
                    );

                keyLimit =
                    parseKeyLimit(
                        req.body
                            .key_limit
                    );

            } catch (error) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            error.message
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
                        ?,
                        ?,
                        ?,

                        ?,

                        1,

                        'unused',
                        ?,
                        ?,

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

                    accountPlan.plan,
                    accountPlan
                        .durationDays,

                    keyLimit,

                    req.user.username
                );

            const created =
                db.getUserById(
                    Number(
                        result
                            .lastInsertRowid
                    )
                );

            logAction(
                req.user.id,
                "create_user",
                "user",
                String(
                    created.id
                )
            );

            return res.json({
                success: true,

                message:
                    "Conta criada com sucesso",

                user:
                    accountPublic(
                        created
                    )
            });

        } catch (error) {
            console.error(
                "Erro ao criar usuário:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao criar usuário"
                });
        }
    }
);

/*
==================================================
OWNER - EDITAR USUÁRIO
==================================================
*/

app.post(
    "/api/admin/users/update",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const id =
                Number(
                    req.body.id
                );

            if (
                !Number.isInteger(
                    id
                ) ||
                id <= 0
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "ID de usuário inválido"
                    });
            }

            const target =
                db.getUserById(
                    id
                );

            if (!target) {
                return res
                    .status(404)
                    .json({
                        success: false,
                        message:
                            "Usuário não encontrado"
                    });
            }

            if (
                normalizeUsername(
                    target.username
                ) ===
                MASTER_OWNER
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "A conta master owner não pode ser alterada"
                    });
            }

            const role =
                req.body.role ===
                    undefined
                    ? target.role
                    : String(
                        req.body.role
                    )
                        .trim()
                        .toLowerCase();

            if (
                ![
                    "owner",
                    "user"
                ].includes(
                    role
                )
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Cargo inválido"
                    });
            }

            let keyLimit =
                target.key_limit;

            if (
                Object.prototype
                    .hasOwnProperty
                    .call(
                        req.body,
                        "key_limit"
                    )
            ) {
                try {
                    keyLimit =
                        parseKeyLimit(
                            req.body
                                .key_limit
                        );

                } catch (error) {
                    return res
                        .status(400)
                        .json({
                            success: false,
                            message:
                                error.message
                        });
                }
            }

            let accountPlan =
                target.account_plan;

            let durationDays =
                target.duration_days;

            if (
                req.body
                    .account_plan !==
                    undefined ||
                req.body.plan !==
                    undefined
            ) {
                try {
                    const parsed =
                        parseAccountPlan(
                            req.body
                        );

                    accountPlan =
                        parsed.plan;

                    durationDays =
                        parsed
                            .durationDays;

                } catch (error) {
                    return res
                        .status(400)
                        .json({
                            success: false,
                            message:
                                error.message
                        });
                }
            }

            let expiresAt =
                target.expires_at;

            /*
            Se a conta já estiver ativa
            e o plano mudar, recalcula
            a validade a partir de agora.
            */

            if (
                target
                    .account_status ===
                    "active" &&
                (
                    accountPlan !==
                        target
                            .account_plan ||
                    durationDays !==
                        target
                            .duration_days
                )
            ) {
                expiresAt =
                    accountPlan ===
                        "lifetime"
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

                accountPlan,

                durationDays,

                expiresAt,

                keyLimit,

                id
            );

            logAction(
                req.user.id,
                "update_user",
                "user",
                String(
                    id
                )
            );

            return res.json({
                success: true,

                message:
                    "Conta atualizada com sucesso",

                user:
                    accountPublic(
                        db.getUserById(
                            id
                        )
                    )
            });

        } catch (error) {
            console.error(
                "Erro ao editar usuário:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao editar usuário"
                });
        }
    }
);

/*
==================================================
OWNER - ATIVAR / DESATIVAR USUÁRIO
==================================================
*/

app.post(
    "/api/admin/users/status",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const id =
                Number(
                    req.body.id
                );

            const enabled =
                req.body.enabled
                    ? 1
                    : 0;

            if (
                !Number.isInteger(
                    id
                ) ||
                id <= 0
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "ID de usuário inválido"
                    });
            }

            const target =
                db.getUserById(
                    id
                );

            if (!target) {
                return res
                    .status(404)
                    .json({
                        success: false,
                        message:
                            "Usuário não encontrado"
                    });
            }

            if (
                normalizeUsername(
                    target.username
                ) ===
                MASTER_OWNER
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "A conta master owner não pode ser desativada"
                    });
            }

            db.prepare(`
                UPDATE users
                SET enabled = ?
                WHERE id = ?
            `).run(
                enabled,
                id
            );

            if (!enabled) {
                db.prepare(`
                    DELETE
                    FROM sessions
                    WHERE user_id = ?
                `).run(
                    id
                );
            }

            logAction(
                req.user.id,

                enabled
                    ? "enable_user"
                    : "disable_user",

                "user",

                String(
                    id
                )
            );

            return res.json({
                success: true,

                enabled:
                    Boolean(
                        enabled
                    )
            });

        } catch (error) {
            console.error(
                "Erro ao alterar usuário:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao alterar usuário"
                });
        }
    }
);

/*
==================================================
OWNER - ALTERAR SENHA
==================================================
*/

app.post(
    "/api/admin/users/password",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const id =
                Number(
                    req.body.id
                );

            const password =
                String(
                    req.body.password ||
                    ""
                );

            if (
                !Number.isInteger(
                    id
                ) ||
                id <= 0
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "ID de usuário inválido"
                    });
            }

            if (
                password.length < 8
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "A senha precisa ter pelo menos 8 caracteres"
                    });
            }

            const target =
                db.getUserById(
                    id
                );

            if (!target) {
                return res
                    .status(404)
                    .json({
                        success: false,
                        message:
                            "Usuário não encontrado"
                    });
            }

            const {
                salt,
                hash
            } = hashPassword(
                password
            );

            db.prepare(`
                UPDATE users
                SET
                    password_hash = ?,
                    password_salt = ?

                WHERE id = ?
            `).run(
                hash,
                salt,
                id
            );

            /*
            Derruba todas as sessões
            da conta após mudar senha.
            */

            db.prepare(`
                DELETE
                FROM sessions
                WHERE user_id = ?
            `).run(
                id
            );

            logAction(
                req.user.id,
                "change_user_password",
                "user",
                String(
                    id
                )
            );

            return res.json({
                success: true,

                message:
                    "Senha alterada com sucesso"
            });

        } catch (error) {
            console.error(
                "Erro ao alterar senha:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao alterar senha"
                });
        }
    }
);

/*
==================================================
OWNER - EXCLUIR USUÁRIO
==================================================
*/

app.delete(
    "/api/admin/users/delete",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const id =
                Number(
                    req.body.id
                );

            if (
                !Number.isInteger(
                    id
                ) ||
                id <= 0
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "ID de usuário inválido"
                    });
            }

            const target =
                db.getUserById(
                    id
                );

            if (!target) {
                return res
                    .status(404)
                    .json({
                        success: false,
                        message:
                            "Usuário não encontrado"
                    });
            }

            if (
                normalizeUsername(
                    target.username
                ) ===
                MASTER_OWNER
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,

                        message:
                            "A conta master owner não pode ser excluída"
                    });
            }

            logAction(
                req.user.id,
                "delete_user",
                "user",
                String(
                    id
                )
            );

            db.prepare(`
                DELETE
                FROM users
                WHERE id = ?
            `).run(
                id
            );

            return res.json({
                success: true,

                message:
                    "Usuário excluído com sucesso"
            });

        } catch (error) {
            console.error(
                "Erro ao excluir usuário:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,

                    message:
                        "Erro interno ao excluir usuário"
                });
        }
    }
);

/*
==================================================
GERAR KEYS
1 A 100 POR VEZ
==================================================
*/

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
                String(
                    req.body.plan ||
                    "1d"
                )
                    .trim()
                    .toLowerCase();

            const quantity =
                req.body.quantity ===
                    undefined
                    ? 1
                    : Number(
                        req.body
                            .quantity
                    );

            if (
                !Number.isInteger(
                    quantity
                ) ||
                quantity < 1 ||
                quantity >
                    MAX_KEYS_PER_REQUEST
            ) {
                return res
                    .status(400)
                    .json({
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
                Object.prototype
                    .hasOwnProperty
                    .call(
                        plans,
                        plan
                    )
            ) {
                days =
                    plans[plan];

            } else if (
                plan ===
                "custom"
            ) {
                days =
                    Number(
                        req.body.days
                    );

                if (
                    !Number.isInteger(
                        days
                    ) ||
                    days <= 0 ||
                    days > 36500
                ) {
                    return res
                        .status(400)
                        .json({
                            success: false,

                            message:
                                "Quantidade de dias inválida"
                        });
                }

            } else {
                return res
                    .status(400)
                    .json({
                        success: false,

                        message:
                            "Plano inválido"
                    });
            }

            const freshUser =
                refreshAccountStatus(
                    db.getUserById(
                        req.user.id
                    )
                );

            if (
                !freshUser ||
                freshUser
                    .account_status ===
                    "expired"
            ) {
                return res
                    .status(403)
                    .json({
                        success: false,

                        code:
                            "ACCOUNT_EXPIRED",

                        message:
                            "Conta expirada"
                    });
            }

            const keyLimit =
                freshUser
                    .key_limit ===
                    null ||
                freshUser
                    .key_limit ===
                    undefined
                    ? null
                    : Number(
                        freshUser
                            .key_limit
                    );

            const generatedCount =
                Number(
                    freshUser
                        .keys_generated ||
                    0
                );

            /*
            LIMITE TOTAL DA CONTA
            */

            if (
                keyLimit !==
                    null &&
                generatedCount +
                    quantity >
                    keyLimit
            ) {
                return res
                    .status(403)
                    .json({
                        success: false,

                        code:
                            "KEY_LIMIT_EXCEEDED",

                        message:
                            "Essa geração ultrapassa o limite de keys da conta",

                        key_limit:
                            keyLimit,

                        keys_generated:
                            generatedCount,

                        keys_remaining:
                            Math.max(
                                0,
                                keyLimit -
                                generatedCount
                            )
                    });
            }

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
                        ?,
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

            /*
            TRANSAÇÃO
            Se alguma key falhar,
            nenhuma das keys do lote é salva.
            */

            const createBatch =
                db.transaction(
                    () => {
                        const generatedKeys =
                            [];

                        for (
                            let i = 0;
                            i < quantity;
                            i++
                        ) {
                            let key;

                            do {
                                key =
                                    generateKey(
                                        prefix
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

                            insertKey.run(
                                key,
                                prefix,
                                `PLAN:${days}`,
                                freshUser.id
                            );

                            generatedKeys
                                .push(
                                    key
                                );
                        }

                        db.prepare(`
                            UPDATE users
                            SET
                                keys_generated =
                                    COALESCE(
                                        keys_generated,
                                        0
                                    ) + ?

                            WHERE id = ?
                        `).run(
                            quantity,
                            freshUser.id
                        );

                        return generatedKeys;
                    }
                );

            const keys =
                createBatch();

            for (
                const key of keys
            ) {
                logAction(
                    freshUser.id,
                    "generate_key",
                    "key",
                    key
                );
            }

            const updatedUser =
                db.getUserById(
                    freshUser.id
                );

            const account =
                accountPublic(
                    updatedUser
                );

            return res.json({
                success: true,

                /*
                Compatibilidade:
                se gerar apenas 1, também
                devolvemos "key".
                */

                key:
                    keys.length === 1
                        ? keys[0]
                        : null,

                keys,

                quantity:
                    keys.length,

                prefix,

                plan,

                days,

                status:
                    "unused",

                usage: {
                    key_limit:
                        account
                            .key_limit,

                    keys_generated:
                        account
                            .keys_generated,

                    keys_remaining:
                        account
                            .keys_remaining,

                    unlimited:
                        account
                            .unlimited_keys
                }
            });

        } catch (error) {
            console.error(
                "Erro ao gerar key:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,

                    message:
                        "Erro interno ao gerar key"
                });
        }
    }
);
