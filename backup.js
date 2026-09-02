const fs = require("fs");
const path = require("path");

const GITHUB_TOKEN = String(process.env.GITHUB_BACKUP_TOKEN || "").trim();
const GITHUB_OWNER = String(process.env.GITHUB_BACKUP_OWNER || "").trim();
const GITHUB_REPO = String(process.env.GITHUB_BACKUP_REPO || "").trim();
const GITHUB_BRANCH = String(process.env.GITHUB_BACKUP_BRANCH || "main").trim();

const ROOT_DIR = __dirname;
const DB_PATH = path.join(ROOT_DIR, "database.db");
const SNAPSHOT_PATH = path.join(ROOT_DIR, ".database-backup-snapshot.db");
const REMOTE_PATH = "backups/latest.db";

const API_BASE = "https://api.github.com";
const BACKUP_DEBOUNCE_MS = 10000;
const PERIODIC_BACKUP_MS = 5 * 60 * 1000;

let db = null;
let originalPrepare = null;
let backupTimer = null;
let backupRunning = false;
let backupQueued = false;
let dirty = false;
let lastBackupAt = null;
let lastBackupError = null;

function configured() {
    return Boolean(GITHUB_TOKEN && GITHUB_OWNER && GITHUB_REPO && GITHUB_BRANCH);
}

function githubHeaders(extra = {}) {
    return {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "external-ios-sqlite-backup",
        ...extra
    };
}

function githubContentsUrl(remotePath = REMOTE_PATH) {
    const encodedPath = remotePath.split("/").map(encodeURIComponent).join("/");
    return `${API_BASE}/repos/${encodeURIComponent(GITHUB_OWNER)}/${encodeURIComponent(GITHUB_REPO)}/contents/${encodedPath}`;
}

async function githubJson(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: githubHeaders(options.headers || {})
    });

    const text = await response.text();
    let data = null;

    if (text) {
        try { data = JSON.parse(text); }
        catch { data = { message: text }; }
    }

    return { response, data };
}

async function getRemoteFile(remotePath = REMOTE_PATH) {
    const url = `${githubContentsUrl(remotePath)}?ref=${encodeURIComponent(GITHUB_BRANCH)}`;
    const { response, data } = await githubJson(url);

    if (response.status === 404) return null;

    if (!response.ok) {
        throw new Error(`GitHub GET falhou (${response.status}): ${data?.message || "erro desconhecido"}`);
    }

    return data;
}

async function downloadBlob(sha) {
    const url = `${API_BASE}/repos/${encodeURIComponent(GITHUB_OWNER)}/${encodeURIComponent(GITHUB_REPO)}/git/blobs/${encodeURIComponent(sha)}`;
    const { response, data } = await githubJson(url);

    if (!response.ok) {
        throw new Error(`GitHub blob falhou (${response.status}): ${data?.message || "erro desconhecido"}`);
    }

    if (!data || data.encoding !== "base64" || !data.content) {
        throw new Error("GitHub retornou blob inválido.");
    }

    return Buffer.from(String(data.content).replace(/\n/g, ""), "base64");
}

async function restoreLatestIfNeeded() {
    if (!configured()) {
        console.warn("[BACKUP] Variáveis do GitHub não configuradas. Restauração automática desativada.");
        return { restored: false, reason: "not_configured" };
    }

    let localExists = false;
    try {
        const stat = fs.statSync(DB_PATH);
        localExists = stat.isFile() && stat.size > 4096;
    } catch {
        localExists = false;
    }

    if (localExists) {
        console.log("[BACKUP] database.db local encontrado; restauração remota não foi necessária.");
        return { restored: false, reason: "local_exists" };
    }

    const remote = await getRemoteFile();

    if (!remote || !remote.sha) {
        console.log("[BACKUP] Nenhum backups/latest.db encontrado no GitHub. O sistema iniciará com banco novo.");
        return { restored: false, reason: "no_remote_backup" };
    }

    const buffer = await downloadBlob(remote.sha);
    if (!buffer || buffer.length < 100) throw new Error("Backup remoto está vazio ou inválido.");

    const tmp = `${DB_PATH}.restore.tmp`;
    fs.writeFileSync(tmp, buffer);
    fs.renameSync(tmp, DB_PATH);

    console.log(`[BACKUP] SQLite restaurado do GitHub (${buffer.length} bytes).`);
    return { restored: true, bytes: buffer.length, sha: remote.sha };
}

function isMutatingSql(sql) {
    const normalized = String(sql || "")
        .replace(/^\s*(?:--[^\n]*\n\s*)*/g, "")
        .trim()
        .toUpperCase();

    return /^(INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|VACUUM|REINDEX|ATTACH|DETACH|PRAGMA\s+(?!TABLE_INFO|INDEX_INFO|INDEX_LIST|FOREIGN_KEY_LIST))/i.test(normalized);
}

function scheduleBackup(reason = "database_change") {
    dirty = true;
    if (!configured()) return;

    if (backupTimer) clearTimeout(backupTimer);

    backupTimer = setTimeout(() => {
        backupTimer = null;
        backupNow(reason).catch((error) => console.error("[BACKUP] Falha:", error.message));
    }, BACKUP_DEBOUNCE_MS);

    if (typeof backupTimer.unref === "function") backupTimer.unref();
}

function installWriteWatcher(database) {
    if (!database || typeof database.prepare !== "function") {
        throw new Error("Instância better-sqlite3 inválida.");
    }

    if (originalPrepare) return;

    db = database;
    originalPrepare = database.prepare.bind(database);

    database.prepare = function patchedPrepare(sql) {
        const statement = originalPrepare(sql);

        if (!isMutatingSql(sql) || !statement || typeof statement.run !== "function") {
            return statement;
        }

        const originalRun = statement.run.bind(statement);

        statement.run = function patchedRun(...args) {
            const result = originalRun(...args);
            if (result && typeof result.changes === "number" && result.changes > 0) {
                scheduleBackup("sqlite_write");
            }
            return result;
        };

        return statement;
    };

    console.log("[BACKUP] Monitor automático de alterações SQLite ativado.");
}

async function makeSnapshot() {
    if (!db) throw new Error("Banco ainda não conectado ao backup manager.");

    try { fs.rmSync(SNAPSHOT_PATH, { force: true }); } catch {}

    await db.backup(SNAPSHOT_PATH);
    const stat = fs.statSync(SNAPSHOT_PATH);

    if (!stat.isFile() || stat.size < 100) throw new Error("Snapshot SQLite inválido.");
    return { path: SNAPSHOT_PATH, size: stat.size };
}

async function uploadLatest(snapshotPath) {
    const fileBuffer = fs.readFileSync(snapshotPath);
    const existing = await getRemoteFile();

    const body = {
        message: `auto backup SQLite ${new Date().toISOString()}`,
        content: fileBuffer.toString("base64"),
        branch: GITHUB_BRANCH
    };

    if (existing?.sha) body.sha = existing.sha;

    const { response, data } = await githubJson(githubContentsUrl(), {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    });

    if (!response.ok) {
        throw new Error(`GitHub PUT falhou (${response.status}): ${data?.message || "erro desconhecido"}`);
    }

    return {
        sha: data?.content?.sha || null,
        commitSha: data?.commit?.sha || null,
        bytes: fileBuffer.length
    };
}

async function backupNow(reason = "manual") {
    if (!configured()) {
        throw new Error("GitHub backup não configurado. Verifique GITHUB_BACKUP_TOKEN, GITHUB_BACKUP_OWNER, GITHUB_BACKUP_REPO e GITHUB_BACKUP_BRANCH.");
    }

    if (!db) throw new Error("Banco ainda não conectado.");

    if (backupRunning) {
        backupQueued = true;
        return { queued: true };
    }

    backupRunning = true;

    try {
        const snapshot = await makeSnapshot();
        const uploaded = await uploadLatest(snapshot.path);

        dirty = false;
        lastBackupAt = new Date().toISOString();
        lastBackupError = null;

        console.log(`[BACKUP] OK (${reason}) - ${uploaded.bytes} bytes enviados para ${GITHUB_OWNER}/${GITHUB_REPO}:${REMOTE_PATH}`);
        return { success: true, reason, at: lastBackupAt, ...uploaded };
    } catch (error) {
        lastBackupError = String(error?.message || error);
        throw error;
    } finally {
        backupRunning = false;
        try { fs.rmSync(SNAPSHOT_PATH, { force: true }); } catch {}

        if (backupQueued) {
            backupQueued = false;
            setTimeout(() => {
                backupNow("queued_change").catch((error) => console.error("[BACKUP] Falha:", error.message));
            }, 1000);
        }
    }
}

function startPeriodicBackup() {
    const interval = setInterval(() => {
        if (!dirty || backupRunning || !configured()) return;
        backupNow("periodic").catch((error) => console.error("[BACKUP] Falha periódica:", error.message));
    }, PERIODIC_BACKUP_MS);

    if (typeof interval.unref === "function") interval.unref();
    return interval;
}

function getStatus() {
    return {
        configured: configured(),
        owner: GITHUB_OWNER || null,
        repo: GITHUB_REPO || null,
        branch: GITHUB_BRANCH || null,
        remote_path: REMOTE_PATH,
        dirty,
        backup_running: backupRunning,
        last_backup_at: lastBackupAt,
        last_error: lastBackupError
    };
}

module.exports = {
    DB_PATH,
    restoreLatestIfNeeded,
    installWriteWatcher,
    scheduleBackup,
    backupNow,
    startPeriodicBackup,
    getStatus
};
