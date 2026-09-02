const backup = require("./backup");

async function main() {
    console.log("[START] Verificando backup SQLite...");

    try {
        await backup.restoreLatestIfNeeded();
    } catch (error) {
        console.error("[START] Falha ao restaurar backup:", error.message);
        process.exit(1);
        return;
    }

    const db = require("./database");
    backup.installWriteWatcher(db);
    backup.startPeriodicBackup();

    require("./server");

    setTimeout(() => {
        backup.backupNow("startup").catch((error) => {
            console.error("[BACKUP] Falha no backup inicial:", error.message);
        });
    }, 5000);

    async function shutdown(signal) {
        console.log(`[START] ${signal} recebido. Salvando ultimo backup...`);

        try {
            await backup.backupNow(`shutdown_${signal}`);
        } catch (error) {
            console.error("[BACKUP] Falha no backup de encerramento:", error.message);
        }

        try { db.close(); } catch {}
        process.exit(0);
    }

    process.once("SIGTERM", () => shutdown("SIGTERM"));
    process.once("SIGINT", () => shutdown("SIGINT"));
}

main().catch((error) => {
    console.error("[START] Erro fatal:", error);
    process.exit(1);
});
