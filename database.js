const Database = require("better-sqlite3");

const db = new Database("database.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

/*
==================================================
KEYS
==================================================
*/

db.exec(`
    CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        key TEXT UNIQUE NOT NULL,
        prefix TEXT NOT NULL,

        status TEXT NOT NULL DEFAULT 'unused',

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT,
        last_reset_at TEXT,
        activated_at TEXT,
        paused_at TEXT,
        remaining_ms INTEGER,

        device_udid TEXT,
        device_bound_at TEXT,
        device_reset_at TEXT,

        created_by_user_id INTEGER,

        FOREIGN KEY (created_by_user_id)
            REFERENCES users(id)
            ON DELETE SET NULL
    );
`);

/*
==================================================
USUÁRIOS DO PAINEL
==================================================

account_status:
    unused   = conta criada, ainda nunca logou
    active   = conta ativada no primeiro login
    expired  = conta expirada

account_plan:
    1d
    7d
    30d
    custom
    lifetime

duration_days:
    NULL para lifetime
    número de dias para os demais planos

key_limit:
    NULL = ilimitado
    número = máximo TOTAL de keys que a conta
    pode gerar durante a existência dela

keys_generated:
    quantidade total já gerada pela conta.
    Deletar uma key NÃO devolve o limite.
==================================================
*/

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT UNIQUE NOT NULL,

        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,

        role TEXT NOT NULL DEFAULT 'user',

        enabled INTEGER NOT NULL DEFAULT 1,

        account_status TEXT NOT NULL DEFAULT 'unused',
        account_plan TEXT NOT NULL DEFAULT 'lifetime',
        duration_days INTEGER,

        activated_at TEXT,
        expires_at TEXT,

        key_limit INTEGER,
        keys_generated INTEGER NOT NULL DEFAULT 0,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_by TEXT,

        last_login_at TEXT
    );
`);

/*
==================================================
SESSÕES DE COLETA DE UDID
==================================================
*/

db.exec(`
    CREATE TABLE IF NOT EXISTS device_enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        token_hash TEXT UNIQUE NOT NULL,
        key_id INTEGER NOT NULL,

        status TEXT NOT NULL DEFAULT 'pending',

        udid TEXT,
        product TEXT,
        ios_version TEXT,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL,
        completed_at TEXT,

        FOREIGN KEY (key_id)
            REFERENCES keys(id)
            ON DELETE CASCADE
    );
`);

/*
==================================================
SESSÕES DO PAINEL
==================================================
*/

db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        token_hash TEXT UNIQUE NOT NULL,

        user_id INTEGER NOT NULL,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    );
`);

/*
==================================================
AUDITORIA
==================================================
*/

db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER,

        action TEXT NOT NULL,
        target_type TEXT,
        target_id TEXT,

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE SET NULL
    );
`);

/*
==================================================
MIGRAÇÕES
==================================================
*/

function tableHasColumn(table, column) {
    const columns = db
        .prepare(`PRAGMA table_info(${table})`)
        .all();

    return columns.some(
        item => item.name === column
    );
}

function addColumnIfMissing(
    table,
    column,
    definition
) {
    if (!tableHasColumn(table, column)) {
        db.prepare(
            `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
        ).run();
    }
}

/*
==================================================
MIGRAÇÕES DE KEYS
==================================================

Keys antigas continuam funcionando.
Somente adicionamos os novos campos.
*/

addColumnIfMissing(
    "keys",
    "paused_at",
    "TEXT"
);

addColumnIfMissing(
    "keys",
    "remaining_ms",
    "INTEGER"
);

addColumnIfMissing(
    "keys",
    "device_udid",
    "TEXT"
);

addColumnIfMissing(
    "keys",
    "device_bound_at",
    "TEXT"
);

addColumnIfMissing(
    "keys",
    "device_reset_at",
    "TEXT"
);

addColumnIfMissing(
    "keys",
    "created_by_user_id",
    "INTEGER REFERENCES users(id) ON DELETE SET NULL"
);

/*
==================================================
MIGRAÇÕES DE USUÁRIOS
==================================================
*/

addColumnIfMissing(
    "users",
    "account_status",
    "TEXT NOT NULL DEFAULT 'unused'"
);

addColumnIfMissing(
    "users",
    "account_plan",
    "TEXT NOT NULL DEFAULT 'lifetime'"
);

addColumnIfMissing(
    "users",
    "duration_days",
    "INTEGER"
);

addColumnIfMissing(
    "users",
    "activated_at",
    "TEXT"
);

addColumnIfMissing(
    "users",
    "expires_at",
    "TEXT"
);

addColumnIfMissing(
    "users",
    "key_limit",
    "INTEGER"
);

addColumnIfMissing(
    "users",
    "keys_generated",
    "INTEGER NOT NULL DEFAULT 0"
);

/*
==================================================
NORMALIZAÇÃO DE DADOS ANTIGOS
==================================================

Contas antigas que já existiam antes deste sistema
continuam válidas como lifetime.

A conta principal "nextaway" também fica lifetime,
ativa e sem limite de keys.
*/

db.prepare(`
    UPDATE users
    SET
        account_plan = COALESCE(account_plan, 'lifetime'),
        account_status = CASE
            WHEN account_status IS NULL
                OR account_status = ''
            THEN 'active'
            ELSE account_status
        END,
        keys_generated = COALESCE(keys_generated, 0)
`).run();

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
    WHERE LOWER(username) = LOWER('nextaway')
`).run();

/*
==================================================
ÍNDICES
==================================================
*/

db.exec(`
    CREATE INDEX IF NOT EXISTS idx_keys_key
    ON keys(key);

    CREATE INDEX IF NOT EXISTS idx_keys_udid
    ON keys(device_udid);

    CREATE INDEX IF NOT EXISTS idx_keys_created_by_user
    ON keys(created_by_user_id);

    CREATE INDEX IF NOT EXISTS idx_users_username
    ON users(username);

    CREATE INDEX IF NOT EXISTS idx_users_role
    ON users(role);

    CREATE INDEX IF NOT EXISTS idx_users_account_status
    ON users(account_status);

    CREATE INDEX IF NOT EXISTS idx_users_expires_at
    ON users(expires_at);

    CREATE INDEX IF NOT EXISTS idx_sessions_token
    ON sessions(token_hash);

    CREATE INDEX IF NOT EXISTS idx_sessions_user
    ON sessions(user_id);

    CREATE INDEX IF NOT EXISTS idx_audit_user
    ON audit_logs(user_id);

    CREATE INDEX IF NOT EXISTS idx_device_enrollments_token
    ON device_enrollments(token_hash);

    CREATE INDEX IF NOT EXISTS idx_device_enrollments_key
    ON device_enrollments(key_id);

    CREATE INDEX IF NOT EXISTS idx_device_enrollments_expires
    ON device_enrollments(expires_at);
`);

/*
==================================================
UTILIDADES
==================================================
*/

db.getKeyByValue = function (key) {
    return db.prepare(`
        SELECT *
        FROM keys
        WHERE key = ?
    `).get(
        String(key || "").trim()
    );
};

db.getUserByUsername = function (username) {
    return db.prepare(`
        SELECT *
        FROM users
        WHERE LOWER(username) = LOWER(?)
    `).get(
        String(username || "").trim()
    );
};

db.getUserById = function (id) {
    return db.prepare(`
        SELECT *
        FROM users
        WHERE id = ?
    `).get(
        Number(id)
    );
};

db.getUserKeyUsage = function (userId) {
    const user = db.getUserById(userId);

    if (!user) {
        return null;
    }

    const limit =
        user.key_limit === null ||
        user.key_limit === undefined
            ? null
            : Number(user.key_limit);

    const generated =
        Number(user.keys_generated || 0);

    return {
        generated,
        limit,
        unlimited: limit === null,
        remaining:
            limit === null
                ? null
                : Math.max(
                    0,
                    limit - generated
                )
    };
};

db.logAction = function (
    userId,
    action,
    targetType = null,
    targetId = null
) {
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
        String(action || ""),
        targetType,
        targetId
    );
};

module.exports = db;

console.log("Banco de dados conectado.");
