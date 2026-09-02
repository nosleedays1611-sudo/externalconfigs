const backup = require("./backup");

async function main() {
    console.log("[START] Verificando/restaurando backup SQLite...");

    let restoreResult;

    try {
        restoreResult = await backup.restoreLatestOnStartup();
    } catch (error) {
        console.error(
            "[START] Falha critica ao verificar/restaurar backup:",
            error.message
        );
        process.exit(1);
        return;
    }

    if (restoreResult?.restored) {
        console.log(
            `[START] Banco remoto restaurado com sucesso (${restoreResult.bytes} bytes).`
        );
    } else if (restoreResult?.reason === "no_remote_backup") {
        console.log(
            "[START] Ainda nao existe backup remoto. O banco local/novo sera usado."
        );
    }

    const db = require("./database");

    backup.installWriteWatcher(db);
    backup.startPeriodicBackup();

    require("./server");

    setTimeout(() => {
        backup.backupNow("startup").catch((error) => {
            console.error(
                "[BACKUP] Falha no backup inicial:",
                error.message
            );
        });
    }, 5000);

    let shuttingDown = false;

    async function shutdown(signal) {
        if (shuttingDown) return;
        shuttingDown = true;

        console.log(
            `[START] ${signal} recebido. Salvando ultimo backup...`
        );

        try {
            await backup.backupNow(`shutdown_${signal}`);
        } catch (error) {
            console.error(
                "[BACKUP] Falha no backup de encerramento:",
                error.message
            );
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
