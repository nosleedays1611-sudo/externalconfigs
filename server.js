const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const path = require("path");
const db = require("./database");

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT) || 80;
const HOST = "0.0.0.0";

const PUBLIC_URL =
    process.env.PUBLIC_URL ||
    "https://externalconfig.shardweb.app";

const OWNER_USERNAME = "nextaway";
const SESSION_HOURS = 24;

/* =========================================================
   MIDDLEWARE
========================================================= */

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

/* =========================================================
   FRONTEND
========================================================= */

app.use(
    express.static(
        path.join(__dirname, "site")
    )
);

app.get("/", (req, res) => {
    res.sendFile(
        path.join(
            __dirname,
            "site",
            "index.html"
        )
    );
});

/* =========================================================
   HEALTH
========================================================= */

app.get("/health", (req, res) => {
    return res.json({
        ok: true,
        message: "API funcionando",
        url: PUBLIC_URL
    });
});

/* =========================================================
   FUNÇÕES GERAIS
========================================================= */

function nowISO() {
    return new Date().toISOString();
}

function generateRandomCode(length = 5) {
    const chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let result = "";

    for (
        let i = 0;
        i < length;
        i++
    ) {
        result += chars[
            crypto.randomInt(
                0,
                chars.length
            )
        ];
    }

    return result;
}

function sanitizePrefix(prefix) {
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

function generateKey(
    prefix = "EXTERNAL"
) {
    prefix =
        sanitizePrefix(prefix);

    return (
        `${prefix}-IOS-` +
        generateRandomCode(5)
    );
}

function calculateExpiration(
    days
) {
    return new Date(
        Date.now() +
        days *
        24 *
        60 *
        60 *
        1000
    ).toISOString();
}

function getDaysFromKey(
    keyData
) {
    if (
        keyData.last_reset_at &&
        String(
            keyData.last_reset_at
        ).startsWith("PLAN:")
    ) {
        return Number(
            String(
                keyData.last_reset_at
            ).replace(
                "PLAN:",
                ""
            )
        );
    }

    return null;
}

function getKey(key) {
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

function checkExpiration(
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
            WHERE key = ?
        `).run(
            keyData.key
        );

        return "expired";
    }

    return keyData.status;
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

/* =========================================================
   PASSWORD / SESSION
========================================================= */

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

function hashToken(token) {
    return crypto
        .createHash("sha256")
        .update(
            String(token)
        )
        .digest("hex");
}

function createSession(
    userId
) {
    const token =
        crypto
            .randomBytes(32)
            .toString("hex");

    const tokenHash =
        hashToken(token);

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

function authRequired(
    req,
    res,
    next
) {
    try {
        const token =
            getBearerToken(req);

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

                    users.id,
                    users.username,
                    users.role,
                    users.enabled

                FROM sessions

                JOIN users
                    ON users.id =
                    sessions.user_id

                WHERE
                    sessions.token_hash = ?
            `).get(
                hashToken(token)
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
            !session.enabled
        ) {
            db.prepare(`
                DELETE
                FROM sessions
                WHERE id = ?
            `).run(
                session.session_id
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
                session.session_id
            );

            return res
                .status(401)
                .json({
                    success: false,
                    message:
                        "Sessão expirada"
                });
        }

        req.user = session;
        req.sessionToken =
            token;

        return next();

    } catch (error) {
        return next(error);
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

function logAction(
    userId,
    action,
    targetType = null,
    targetId = null
) {
    try {
        db.prepare(`
            INSERT INTO audit_logs (
                user_id,
                action,
                target_type,
                target_id
            )
            VALUES (?, ?, ?, ?)
        `).run(
            userId || null,
            String(
                action || ""
            ),
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

/* =========================================================
   CRIAR OWNER "nextaway"
========================================================= */

function ensureOwner() {
    const owner =
        db.prepare(`
            SELECT *
            FROM users
            WHERE LOWER(username)
                = LOWER(?)
        `).get(
            OWNER_USERNAME
        );

    if (owner) {
        if (
            owner.role !==
                "owner" ||
            !owner.enabled
        ) {
            db.prepare(`
                UPDATE users
                SET
                    role = 'owner',
                    enabled = 1
                WHERE id = ?
            `).run(
                owner.id
            );
        }

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
            "Defina NEXTAWAY_PASSWORD no ambiente do servidor com pelo menos 8 caracteres e reinicie."
        );

        return;
    }

    const {
        salt,
        hash
    } = hashPassword(
        password
    );

    db.prepare(`
        INSERT INTO users (
            username,
            password_hash,
            password_salt,
            role,
            enabled,
            created_by
        )
        VALUES (
            ?,
            ?,
            ?,
            'owner',
            1,
            'system'
        )
    `).run(
        OWNER_USERNAME,
        hash,
        salt
    );

    console.log(
        'Conta owner "nextaway" criada.'
    );
}

ensureOwner();

/* =========================================================
   AUTH - LOGIN
========================================================= */

app.post(
    "/api/auth/login",
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

            if (
                !username ||
                !password
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Usuário e senha são obrigatórios"
                    });
            }

            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE LOWER(username)
                        = LOWER(?)
                `).get(
                    username
                );

            if (
                !user ||
                !user.enabled ||
                !verifyPassword(
                    password,
                    user.password_salt,
                    user.password_hash
                )
            ) {
                return res
                    .status(401)
                    .json({
                        success: false,
                        message:
                            "Usuário ou senha inválidos"
                    });
            }

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

            const session =
                createSession(
                    user.id
                );

            logAction(
                user.id,
                "login",
                "user",
                String(user.id)
            );

            return res.json({
                success: true,

                token:
                    session.token,

                expires_at:
                    session.expiresAt,

                user: {
                    id:
                        user.id,

                    username:
                        user.username,

                    role:
                        user.role
                }
            });

        } catch (error) {
            console.error(
                "Erro no login:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno no login"
                });
        }
    }
);

/* =========================================================
   AUTH - ME
========================================================= */

app.get(
    "/api/auth/me",
    authRequired,
    (req, res) => {
        return res.json({
            success: true,

            user: {
                id:
                    req.user.id,

                username:
                    req.user.username,

                role:
                    req.user.role
            }
        });
    }
);

/* =========================================================
   AUTH - LOGOUT
========================================================= */

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

/* =========================================================
   OWNER - LISTAR USUÁRIOS
========================================================= */

app.get(
    "/api/admin/users",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const users =
                db.prepare(`
                    SELECT
                        id,
                        username,
                        role,
                        enabled,
                        created_at,
                        created_by,
                        last_login_at

                    FROM users

                    ORDER BY id DESC
                `).all();

            return res.json({
                success: true,
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

/* =========================================================
   OWNER - CRIAR USUÁRIO
========================================================= */

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
                username ===
                OWNER_USERNAME
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
                db.prepare(`
                    SELECT id
                    FROM users
                    WHERE LOWER(username)
                        = LOWER(?)
                `).get(
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
                        created_by
                    )
                    VALUES (
                        ?,
                        ?,
                        ?,
                        'user',
                        1,
                        ?
                    )
                `).run(
                    username,
                    hash,
                    salt,
                    req.user.username
                );

            logAction(
                req.user.id,
                "create_user",
                "user",
                String(
                    result
                        .lastInsertRowid
                )
            );

            return res.json({
                success: true,

                message:
                    "Usuário criado com sucesso",

                user: {
                    id:
                        Number(
                            result
                                .lastInsertRowid
                        ),

                    username,

                    role:
                        "user",

                    enabled:
                        true
                }
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

/* =========================================================
   OWNER - ATIVAR / DESATIVAR USUÁRIO
========================================================= */

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
                !Number.isInteger(id) ||
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
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE id = ?
                `).get(id);

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
                target.role ===
                "owner"
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "A conta owner não pode ser desativada"
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

/* =========================================================
   OWNER - ALTERAR SENHA
========================================================= */

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
                !Number.isInteger(id) ||
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
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE id = ?
                `).get(id);

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

            db.prepare(`
                DELETE
                FROM sessions
                WHERE user_id = ?
            `).run(id);

            logAction(
                req.user.id,
                "change_user_password",
                "user",
                String(id)
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

/* =========================================================
   OWNER - EXCLUIR USUÁRIO
========================================================= */

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
                !Number.isInteger(id) ||
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
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE id = ?
                `).get(id);

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
                target.role ===
                "owner"
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "A conta owner não pode ser excluída"
                    });
            }

            logAction(
                req.user.id,
                "delete_user",
                "user",
                String(id)
            );

            db.prepare(`
                DELETE
                FROM users
                WHERE id = ?
            `).run(id);

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

/* =========================================================
   GERAR KEY
   REQUER LOGIN DO PAINEL
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
                req.body.plan ||
                "1d";

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
                    days <= 0
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
                `).get(key)
            );

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
                    device_reset_at
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
                    NULL
                )
            `).run(
                key,
                prefix,
                `PLAN:${days}`
            );

            logAction(
                req.user.id,
                "generate_key",
                "key",
                key
            );

            return res.json({
                success: true,
                key,
                prefix,
                plan,
                days,
                status:
                    "unused",
                device_bound:
                    false
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

/* =========================================================
   CHECK KEY
   PÚBLICO - USADO PELA IPA
========================================================= */

app.post(
    "/api/keys/check",
    (req, res) => {
        try {
            const key =
                String(
                    req.body.key ||
                    ""
                ).trim();

            if (!key) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key não informada"
                    });
            }

            const keyData =
                getKey(key);

            if (!keyData) {
                return res.json({
                    success: true,
                    found: false,
                    message:
                        "Key não encontrada"
                });
            }

            const status =
                checkExpiration(
                    keyData
                );

            const days =
                getDaysFromKey(
                    keyData
                );

            return res.json({
                success: true,
                found: true,

                key:
                    keyData.key,

                prefix:
                    keyData.prefix,

                status,
                days,

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
                    keyData.device_bound_at
            });

        } catch (error) {
            console.error(
                "Erro ao verificar key:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao verificar key"
                });
        }
    }
);

/* =========================================================
   VINCULAR UDID
   PÚBLICO - USADO PELA IPA
========================================================= */

app.post(
    "/api/keys/device/bind",
    (req, res) => {
        try {
            const key =
                String(
                    req.body.key ||
                    ""
                ).trim();

            const udid =
                normalizeUDID(
                    req.body.udid
                );

            if (
                !key ||
                !udid
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key e UDID são obrigatórios"
                    });
            }

            if (
                !validUDID(
                    udid
                )
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "UDID inválido"
                    });
            }

            const keyData =
                getKey(key);

            if (!keyData) {
                return res
                    .status(404)
                    .json({
                        success: false,
                        message:
                            "Key não encontrada"
                    });
            }

            const status =
                checkExpiration(
                    keyData
                );

            if (
                status ===
                "expired"
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key expirada"
                    });
            }

            if (
                status ===
                "paused"
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key pausada"
                    });
            }

            if (
                keyData.device_udid
            ) {
                const saved =
                    normalizeUDID(
                        keyData
                            .device_udid
                    );

                if (
                    saved !==
                    udid
                ) {
                    return res
                        .status(403)
                        .json({
                            success: false,
                            code:
                                "DEVICE_MISMATCH",
                            message:
                                "Key usada em outro dispositivo."
                        });
                }

                return res.json({
                    success: true,
                    already_bound:
                        true,
                    device_match:
                        true,
                    message:
                        "Dispositivo já vinculado"
                });
            }

            const boundAt =
                nowISO();

            const update =
                db.prepare(`
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

            if (
                update.changes !==
                1
            ) {
                const latest =
                    getKey(
                        keyData.key
                    );

                if (
                    latest &&
                    latest
                        .device_udid &&
                    normalizeUDID(
                        latest
                            .device_udid
                    ) !==
                        udid
                ) {
                    return res
                        .status(403)
                        .json({
                            success: false,
                            code:
                                "DEVICE_MISMATCH",
                            message:
                                "Key usada em outro dispositivo."
                        });
                }
            }

            return res.json({
                success: true,
                already_bound:
                    false,
                device_match:
                    true,
                device_bound_at:
                    boundAt,
                message:
                    "Dispositivo vinculado com sucesso"
            });

        } catch (error) {
            console.error(
                "Erro ao vincular UDID:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao vincular dispositivo"
                });
        }
    }
);

/* =========================================================
   VALIDAR UDID
   PÚBLICO - USADO PELA IPA
========================================================= */

app.post(
    "/api/keys/device/verify",
    (req, res) => {
        try {
            const key =
                String(
                    req.body.key ||
                    ""
                ).trim();

            const udid =
                normalizeUDID(
                    req.body.udid
                );

            if (
                !key ||
                !udid
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key e UDID são obrigatórios"
                    });
            }

            const keyData =
                getKey(key);

            if (!keyData) {
                return res
                    .status(404)
                    .json({
                        success: false,
                        message:
                            "Key não encontrada"
                    });
            }

            if (
                !keyData.device_udid
            ) {
                return res
                    .status(409)
                    .json({
                        success: false,
                        code:
                            "DEVICE_NOT_BOUND",
                        message:
                            "Key ainda não possui dispositivo vinculado"
                    });
            }

            const match =
                normalizeUDID(
                    keyData
                        .device_udid
                ) === udid;

            if (!match) {
                return res
                    .status(403)
                    .json({
                        success: false,
                        code:
                            "DEVICE_MISMATCH",
                        message:
                            "Key usada em outro dispositivo."
                    });
            }

            return res.json({
                success: true,
                device_match:
                    true
            });

        } catch (error) {
            console.error(
                "Erro ao validar UDID:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao validar dispositivo"
                });
        }
    }
);

/* =========================================================
   ATIVAR KEY
   PÚBLICO - USADO PELA IPA
========================================================= */

app.post(
    "/api/keys/activate",
    (req, res) => {
        try {
            const key =
                String(
                    req.body.key ||
                    ""
                ).trim();

            const udid =
                normalizeUDID(
                    req.body.udid
                );

            if (!key) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key não informada"
                    });
            }

            const keyData =
                getKey(key);

            if (!keyData) {
                return res
                    .status(404)
                    .json({
                        success: false,
                        message:
                            "Key não encontrada"
                    });
            }

            const currentStatus =
                checkExpiration(
                    keyData
                );

            if (
                currentStatus ===
                "paused"
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key está pausada"
                    });
            }

            if (
                currentStatus ===
                "expired"
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key expirada"
                    });
            }

            if (
                !keyData.device_udid
            ) {
                return res
                    .status(409)
                    .json({
                        success: false,
                        code:
                            "DEVICE_NOT_BOUND",
                        message:
                            "Obtenha e vincule o UDID antes de ativar a key"
                    });
            }

            if (
                !udid ||
                normalizeUDID(
                    keyData
                        .device_udid
                ) !== udid
            ) {
                return res
                    .status(403)
                    .json({
                        success: false,
                        code:
                            "DEVICE_MISMATCH",
                        message:
                            "Key usada em outro dispositivo."
                    });
            }

            if (
                currentStatus ===
                "active"
            ) {
                return res.json({
                    success: true,

                    key:
                        keyData.key,

                    status:
                        "active",

                    already_active:
                        true,

                    activated_at:
                        keyData
                            .activated_at,

                    expires_at:
                        keyData
                            .expires_at,

                    device_match:
                        true
                });
            }

            if (
                currentStatus !==
                "unused"
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key não pode ser ativada"
                    });
            }

            const days =
                getDaysFromKey(
                    keyData
                );

            if (
                !days ||
                days <= 0
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Plano da key não encontrado"
                    });
            }

            const activatedAt =
                nowISO();

            const expiresAt =
                calculateExpiration(
                    days
                );

            db.prepare(`
                UPDATE keys
                SET
                    status = 'active',
                    activated_at = ?,
                    expires_at = ?,
                    paused_at = NULL,
                    remaining_ms = NULL
                WHERE key = ?
            `).run(
                activatedAt,
                expiresAt,
                keyData.key
            );

            return res.json({
                success: true,

                key:
                    keyData.key,

                status:
                    "active",

                days,

                activated_at:
                    activatedAt,

                expires_at:
                    expiresAt,

                device_match:
                    true
            });

        } catch (error) {
            console.error(
                "Erro ao ativar key:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao ativar key"
                });
        }
    }
);

/* =========================================================
   RESETAR KEY
   REQUER LOGIN
   NÃO RESETA O UDID
========================================================= */

app.post(
    "/api/keys/reset",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(
                    req.body.key ||
                    ""
                ).trim();

            if (!key) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key não informada"
                    });
            }

            const keyData =
                getKey(key);

            if (!keyData) {
                return res
                    .status(404)
                    .json({
                        success: false,
                        message:
                            "Key não encontrada"
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
                WHERE key = ?
            `).run(
                keyData.key
            );

            logAction(
                req.user.id,
                "reset_key",
                "key",
                keyData.key
            );

            return res.json({
                success: true,

                message:
                    "Key resetada com sucesso",

                key:
                    keyData.key,

                status:
                    "unused",

                days:
                    getDaysFromKey(
                        keyData
                    ),

                device_bound:
                    Boolean(
                        keyData.device_udid
                    )
            });

        } catch (error) {
            console.error(
                "Erro ao resetar key:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao resetar key"
                });
        }
    }
);

/* =========================================================
   RESETAR SOMENTE UDID
   REQUER LOGIN
========================================================= */

app.post(
    "/api/keys/device/reset",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(
                    req.body.key ||
                    ""
                ).trim();

            if (!key) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key não informada"
                    });
            }

            const keyData =
                getKey(key);

            if (!keyData) {
                return res
                    .status(404)
                    .json({
                        success: false,
                        message:
                            "Key não encontrada"
                    });
            }

            const resetAt =
                nowISO();

            db.prepare(`
                UPDATE keys
                SET
                    device_udid = NULL,
                    device_bound_at = NULL,
                    device_reset_at = ?
                WHERE key = ?
            `).run(
                resetAt,
                keyData.key
            );

            logAction(
                req.user.id,
                "reset_udid",
                "key",
                keyData.key
            );

            return res.json({
                success: true,

                message:
                    "UDID resetado com sucesso",

                key:
                    keyData.key,

                device_bound:
                    false,

                device_reset_at:
                    resetAt
            });

        } catch (error) {
            console.error(
                "Erro ao resetar UDID:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao resetar UDID"
                });
        }
    }
);

/* =========================================================
   PAUSAR KEY
   REQUER LOGIN
========================================================= */

app.post(
    "/api/keys/pause",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(
                    req.body.key ||
                    ""
                ).trim();

            if (!key) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key não informada"
                    });
            }

            const keyData =
                getKey(key);

            if (!keyData) {
                return res
                    .status(404)
                    .json({
                        success: false,
                        message:
                            "Key não encontrada"
                    });
            }

            const currentStatus =
                checkExpiration(
                    keyData
                );

            if (
                currentStatus !==
                "active"
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Somente keys ativas podem ser pausadas"
                    });
            }

            if (
                !keyData.expires_at
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key não possui data de expiração"
                    });
            }

            const remaining =
                new Date(
                    keyData.expires_at
                ).getTime() -
                Date.now();

            if (
                remaining <= 0
            ) {
                db.prepare(`
                    UPDATE keys
                    SET status = 'expired'
                    WHERE key = ?
                `).run(
                    keyData.key
                );

                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key já está expirada"
                    });
            }

            const pausedAt =
                nowISO();

            db.prepare(`
                UPDATE keys
                SET
                    status = 'paused',
                    paused_at = ?,
                    remaining_ms = ?,
                    expires_at = NULL
                WHERE key = ?
            `).run(
                pausedAt,
                remaining,
                keyData.key
            );

            logAction(
                req.user.id,
                "pause_key",
                "key",
                keyData.key
            );

            return res.json({
                success: true,

                message:
                    "Key pausada com sucesso",

                key:
                    keyData.key,

                status:
                    "paused",

                paused_at:
                    pausedAt,

                remaining_ms:
                    remaining
            });

        } catch (error) {
            console.error(
                "Erro ao pausar key:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao pausar key"
                });
        }
    }
);

/* =========================================================
   RETOMAR KEY
   REQUER LOGIN
========================================================= */

app.post(
    "/api/keys/resume",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(
                    req.body.key ||
                    ""
                ).trim();

            if (!key) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key não informada"
                    });
            }

            const keyData =
                getKey(key);

            if (!keyData) {
                return res
                    .status(404)
                    .json({
                        success: false,
                        message:
                            "Key não encontrada"
                    });
            }

            if (
                keyData.status !==
                "paused"
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key não está pausada"
                    });
            }

            if (
                !keyData.remaining_ms ||
                Number(
                    keyData
                        .remaining_ms
                ) <= 0
            ) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key não possui tempo restante"
                    });
            }

            const expiresAt =
                new Date(
                    Date.now() +
                    Number(
                        keyData
                            .remaining_ms
                    )
                ).toISOString();

            db.prepare(`
                UPDATE keys
                SET
                    status = 'active',
                    expires_at = ?,
                    paused_at = NULL,
                    remaining_ms = NULL
                WHERE key = ?
            `).run(
                expiresAt,
                keyData.key
            );

            logAction(
                req.user.id,
                "resume_key",
                "key",
                keyData.key
            );

            return res.json({
                success: true,

                message:
                    "Key retomada com sucesso",

                key:
                    keyData.key,

                status:
                    "active",

                expires_at:
                    expiresAt
            });

        } catch (error) {
            console.error(
                "Erro ao retomar key:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao retomar key"
                });
        }
    }
);

/* =========================================================
   DELETAR KEY
   REQUER LOGIN
========================================================= */

app.delete(
    "/api/keys/delete",
    authRequired,
    (req, res) => {
        try {
            const key =
                String(
                    req.body.key ||
                    ""
                ).trim();

            if (!key) {
                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Key não informada"
                    });
            }

            const keyData =
                getKey(key);

            if (!keyData) {
                return res
                    .status(404)
                    .json({
                        success: false,
                        message:
                            "Key não encontrada"
                    });
            }

            db.prepare(`
                DELETE
                FROM keys
                WHERE key = ?
            `).run(
                keyData.key
            );

            logAction(
                req.user.id,
                "delete_key",
                "key",
                keyData.key
            );

            return res.json({
                success: true,

                message:
                    "Key deletada com sucesso",

                key:
                    keyData.key
            });

        } catch (error) {
            console.error(
                "Erro ao deletar key:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao deletar key"
                });
        }
    }
);

/* =========================================================
   LISTAR KEYS
   REQUER LOGIN
========================================================= */

app.get(
    "/api/keys",
    authRequired,
    (req, res) => {
        try {
            const keys =
                db.prepare(`
                    SELECT
                        id,
                        key,
                        prefix,
                        status,
                        created_at,
                        activated_at,
                        expires_at,
                        paused_at,
                        remaining_ms,
                        last_reset_at,
                        device_udid,
                        device_bound_at,
                        device_reset_at

                    FROM keys

                    ORDER BY id DESC
                `).all();

            const result =
                keys.map(
                    (keyData) => ({
                        ...keyData,

                        status:
                            checkExpiration(
                                keyData
                            ),

                        days:
                            getDaysFromKey(
                                keyData
                            ),

                        device_bound:
                            Boolean(
                                keyData
                                    .device_udid
                            )
                    })
                );

            return res.json({
                success: true,
                total:
                    result.length,
                keys:
                    result
            });

        } catch (error) {
            console.error(
                "Erro ao listar keys:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao listar keys"
                });
        }
    }
);

/* =========================================================
   AUDITORIA
   SOMENTE OWNER
========================================================= */

app.get(
    "/api/admin/audit",
    authRequired,
    ownerRequired,
    (req, res) => {
        try {
            const logs =
                db.prepare(`
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

                    ORDER BY
                        audit_logs.id
                        DESC

                    LIMIT 500
                `).all();

            return res.json({
                success: true,
                logs
            });

        } catch (error) {
            console.error(
                "Erro ao listar auditoria:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false,
                    message:
                        "Erro interno ao listar auditoria"
                });
        }
    }
);

/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {
        return res
            .status(404)
            .json({
                success: false,
                message:
                    "Rota não encontrada"
            });
    }
);

/* =========================================================
   ERRO GLOBAL
========================================================= */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {
        console.error(
            "Erro global:",
            error
        );

        return res
            .status(500)
            .json({
                success: false,
                message:
                    "Erro interno do servidor"
            });
    }
);

/* =========================================================
   INICIAR SERVIDOR
========================================================= */

app.listen(
    PORT,
    HOST,
    () => {
        console.log(
            "================================="
        );

        console.log(
            `Servidor: http://${HOST}:${PORT}`
        );

        console.log(
            `API pública: ${PUBLIC_URL}`
        );

        console.log(
            `Painel: ${PUBLIC_URL}/`
        );

        console.log(
            `Health: ${PUBLIC_URL}/health`
        );

        console.log(
            "Prefixo padrão: EXTERNAL"
        );

        console.log(
            "Owner: nextaway"
        );

        console.log(
            "================================="
        );
    }
);
