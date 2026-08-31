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
        device_reset_at TEXT
    );
`);

/*
==================================================
USUÁRIOS DO PAINEL
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

        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_by TEXT,

        last_login_at TEXT
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

    CREATE INDEX IF NOT EXISTS idx_users_username
    ON users(username);

    CREATE INDEX IF NOT EXISTS idx_sessions_token
    ON sessions(token_hash);

    CREATE INDEX IF NOT EXISTS idx_sessions_user
    ON sessions(user_id);
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
