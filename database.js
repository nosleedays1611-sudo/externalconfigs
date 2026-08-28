const Database = require("better-sqlite3");

const db = new Database("database.db");

db.pragma("journal_mode = WAL");

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
        remaining_ms INTEGER
    );
`);

function addColumnIfMissing(column, definition) {
    try {
        db.prepare(`ALTER TABLE keys ADD COLUMN ${column} ${definition}`).run();
    } catch (error) {
        if (!error.message.includes("duplicate column name")) {
            throw error;
        }
    }
}

addColumnIfMissing("paused_at", "TEXT");
addColumnIfMissing("remaining_ms", "INTEGER");

module.exports = db;

console.log("Banco de dados conectado.");