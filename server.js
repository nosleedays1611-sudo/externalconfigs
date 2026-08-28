const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const path = require("path");
const db = require("./database");

const app = express();

/* =========================
   SHARD CLOUD / SERVIDOR
========================= */

const PORT = 80;
const HOST = "0.0.0.0";

const PUBLIC_URL = "https://externalconfig.shardweb.app";

/* =========================
   CORS / JSON
========================= */

app.use(cors({
    origin: true,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type"]
}));

app.use(express.json());

/* =========================
   FRONTEND
========================= */

app.use(express.static(path.join(__dirname, "site")));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "site", "index.html"));
});

/* =========================
   HEALTH
========================= */

app.get("/health", (req, res) => {
    res.json({
        ok: true,
        message: "API funcionando",
        url: PUBLIC_URL
    });
});

/* =========================
   FUNÇÕES
========================= */

function generateRandomCode(length = 5) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let result = "";

    for (let i = 0; i < length; i++) {
        result += chars[crypto.randomInt(0, chars.length)];
    }

    return result;
}

function sanitizePrefix(prefix) {
    prefix = String(prefix || "EXT")
        .trim()
        .toUpperCase()
        .replace(/[^A-Z0-9_-]/g, "");

    return prefix || "EXT";
}

function generateKey(prefix = "EXT") {
    prefix = sanitizePrefix(prefix);

    return `${prefix}-IOS-${generateRandomCode(5)}`;
}

function calculateExpiration(days) {
    return new Date(
        Date.now() + days * 24 * 60 * 60 * 1000
    ).toISOString();
}

function getDaysFromKey(keyData) {
    if (
        keyData.last_reset_at &&
        String(keyData.last_reset_at).startsWith("PLAN:")
    ) {
        return Number(
            String(keyData.last_reset_at).replace("PLAN:", "")
        );
    }

    return null;
}

function getKey(key) {
    return db
        .prepare("SELECT * FROM keys WHERE key = ?")
        .get(String(key || "").trim());
}

function checkExpiration(keyData) {
    if (
        keyData.status === "active" &&
        keyData.expires_at &&
        new Date(keyData.expires_at).getTime() <= Date.now()
    ) {
        db.prepare(`
            UPDATE keys
            SET status = 'expired'
            WHERE key = ?
        `).run(keyData.key);

        return "expired";
    }

    return keyData.status;
}

/* =========================
   GERAR KEY
========================= */

app.post("/api/keys/generate", (req, res) => {
    try {
        const prefix = sanitizePrefix(
            req.body.prefix || "EXT"
        );

        const plan = req.body.plan || "1d";

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
                days <= 0
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

        let key;

        do {
            key = generateKey(prefix);

        } while (
            db
                .prepare(
                    "SELECT id FROM keys WHERE key = ?"
                )
                .get(key)
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
                remaining_ms
            )
            VALUES (
                ?,
                ?,
                'unused',
                NULL,
                ?,
                NULL,
                NULL,
                NULL
            )
        `).run(
            key,
            prefix,
            `PLAN:${days}`
        );

        return res.json({
            success: true,
            key,
            prefix,
            plan,
            days,
            status: "unused"
        });

    } catch (error) {
        console.error(
            "Erro ao gerar key:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Erro interno ao gerar key"
        });
    }
});

/* =========================
   CHECK KEY
========================= */

app.post("/api/keys/check", (req, res) => {
    try {
        const { key } = req.body;

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
            checkExpiration(keyData);

        const days =
            getDaysFromKey(keyData);

        return res.json({
            success: true,
            found: true,

            key: keyData.key,
            prefix: keyData.prefix,

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
                keyData.remaining_ms
        });

    } catch (error) {
        console.error(
            "Erro ao verificar key:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Erro interno ao verificar key"
        });
    }
});

/* =========================
   ATIVAR KEY
========================= */

app.post("/api/keys/activate", (req, res) => {
    try {
        const { key } = req.body;

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

        const currentStatus =
            checkExpiration(keyData);

        if (currentStatus === "active") {
            return res.status(400).json({
                success: false,
                message: "Key já está ativa"
            });
        }

        if (currentStatus === "paused") {
            return res.status(400).json({
                success: false,
                message:
                    "Key está pausada. Use resume para continuar."
            });
        }

        if (currentStatus === "expired") {
            return res.status(400).json({
                success: false,
                message: "Key expirada"
            });
        }

        if (currentStatus !== "unused") {
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

        const activatedAt =
            new Date().toISOString();

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
            WHERE key = ?
        `).run(
            activatedAt,
            expiresAt,
            keyData.key
        );

        return res.json({
            success: true,

            key: keyData.key,

            status: "active",

            days,

            activated_at:
                activatedAt,

            expires_at:
                expiresAt
        });

    } catch (error) {
        console.error(
            "Erro ao ativar key:",
            error
        );

        return res.status(500).json({
            success: false,
            message: "Erro interno ao ativar key"
        });
    }
});

/* =========================
   RESET KEY
========================= */

app.post("/api/keys/reset", (req, res) => {
    try {
        const { key } = req.body;

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

        return res.json({
            success: true,

            message:
                "Key resetada com sucesso",

            key:
                keyData.key,

            status:
                "unused",

            days:
                getDaysFromKey(keyData)
        });

    } catch (error) {
        console.error(
            "Erro ao resetar key:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Erro interno ao resetar key"
        });
    }
});

/* =========================
   PAUSAR KEY
========================= */

app.post("/api/keys/pause", (req, res) => {
    try {
        const { key } = req.body;

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

        const currentStatus =
            checkExpiration(keyData);

        if (currentStatus !== "active") {
            return res.status(400).json({
                success: false,
                message:
                    "Somente keys ativas podem ser pausadas"
            });
        }

        if (!keyData.expires_at) {
            return res.status(400).json({
                success: false,
                message:
                    "Key não possui data de expiração"
            });
        }

        const now =
            Date.now();

        const expiration =
            new Date(
                keyData.expires_at
            ).getTime();

        const remaining =
            expiration - now;

        if (remaining <= 0) {
            db.prepare(`
                UPDATE keys
                SET status = 'expired'
                WHERE key = ?
            `).run(
                keyData.key
            );

            return res.status(400).json({
                success: false,
                message: "Key já está expirada"
            });
        }

        const pausedAt =
            new Date().toISOString();

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

        return res.status(500).json({
            success: false,
            message:
                "Erro interno ao pausar key"
        });
    }
});

/* =========================
   RETOMAR KEY
========================= */

app.post("/api/keys/resume", (req, res) => {
    try {
        const { key } = req.body;

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

        if (
            keyData.status !== "paused"
        ) {
            return res.status(400).json({
                success: false,
                message: "Key não está pausada"
            });
        }

        if (
            !keyData.remaining_ms ||
            Number(keyData.remaining_ms) <= 0
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Key não possui tempo restante"
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
            WHERE key = ?
        `).run(
            expiresAt,
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

        return res.status(500).json({
            success: false,
            message:
                "Erro interno ao retomar key"
        });
    }
});

/* =========================
   DELETAR KEY
========================= */

app.delete("/api/keys/delete", (req, res) => {
    try {
        const { key } = req.body;

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

        db.prepare(`
            DELETE FROM keys
            WHERE key = ?
        `).run(
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

        return res.status(500).json({
            success: false,
            message:
                "Erro interno ao deletar key"
        });
    }
});

/* =========================
   LISTAR KEYS
========================= */

app.get("/api/keys", (req, res) => {
    try {
        const keys = db
            .prepare(`
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
                    last_reset_at
                FROM keys
                ORDER BY id DESC
            `)
            .all();

        const result =
            keys.map((keyData) => {

                const status =
                    checkExpiration(
                        keyData
                    );

                return {
                    ...keyData,

                    status,

                    days:
                        getDaysFromKey(
                            keyData
                        )
                };
            });

        return res.json({
            success: true,
            total: result.length,
            keys: result
        });

    } catch (error) {
        console.error(
            "Erro ao listar keys:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Erro interno ao listar keys"
        });
    }
});

/* =========================
   404
========================= */

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "Rota não encontrada"
    });
});

/* =========================
   ERRO GLOBAL
========================= */

app.use((error, req, res, next) => {
    console.error(
        "Erro global:",
        error
    );

    res.status(500).json({
        success: false,
        message: "Erro interno do servidor"
    });
});

/* =========================
   INICIAR SERVIDOR
========================= */

app.listen(PORT, HOST, () => {
    console.log(
        "================================="
    );

    console.log(
        "Banco de dados conectado."
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
        "CORS habilitado."
    );

    console.log(
        "================================="
    );
});
