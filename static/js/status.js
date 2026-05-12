function loadSystemStatus() {
  const loadingEl = document.getElementById("system-status-loading");
  const contentEl = document.getElementById("system-status-content");
  const schedulerEl = document.getElementById("scheduler-status-card");
  const notificationsEl = document.getElementById("notifications-status-card");
  const storageEl = document.getElementById("storage-status-card");

  if (!loadingEl || !contentEl || !schedulerEl || !notificationsEl || !storageEl) {
    return;
  }

  loadingEl.style.display = "block";
  contentEl.style.display = "none";

  fetch("/api/system/status")
    .then((r) => r.json())
    .then((data) => {
      const scheduler = data.scheduler || {};
      const notifications = data.notifications || {};
      const storage = data.storage || {};

      schedulerEl.innerHTML = `
        <div class="mb-1"><strong>Enabled:</strong> ${scheduler.enabled ? "Yes" : "No"}</div>
        <div class="mb-1"><strong>Running:</strong> ${scheduler.running ? "Yes" : "No"}</div>
        <div class="mb-1"><strong>Schedule:</strong> ${scheduler.scheduleTime || "N/A"} (${scheduler.timezone || "local"})</div>
        <div class="mb-1"><strong>Target registries:</strong> <code>${scheduler.targetRegistries || "all"}</code></div>
        <div class="mb-1"><strong>Mode:</strong> ${scheduler.mode || "all"}</div>
        <div class="mb-1"><strong>Repo pattern:</strong> <code>${scheduler.repoPattern || "*"}</code></div>
        <div class="mb-1"><strong>Include all tags:</strong> ${scheduler.includeAllTags ? "Yes" : "No"}</div>
        <div class="mb-1"><strong>Dry run:</strong> ${scheduler.dryRun ? "Yes" : "No"}</div>
        <div class="mb-1"><strong>Last run at:</strong> ${scheduler.lastRunAt || "Never"}</div>
        <div class="mb-1"><strong>Last error:</strong> ${scheduler.lastError || "None"}</div>
        <div class="mt-2"><strong>Last summary:</strong><br>
          <small class="text-muted">${scheduler.lastRunSummary ? JSON.stringify(scheduler.lastRunSummary) : "No runs yet"}</small>
        </div>
      `;

      notificationsEl.innerHTML = `
        <div class="mb-1"><strong>Email enabled:</strong> ${notifications.emailEnabled ? "Yes" : "No"}</div>
        <div class="mb-1"><strong>Telegram enabled:</strong> ${notifications.telegramEnabled ? "Yes" : "No"}</div>
      `;

      storageEl.innerHTML = `
        <div class="mb-1"><strong>SQLite DB:</strong> <code>${storage.dbPath || "N/A"}</code></div>
        <div class="mb-1"><strong>Registry config file:</strong> <code>${storage.configFile || "N/A"}</code></div>
      `;

      loadingEl.style.display = "none";
      contentEl.style.display = "block";
    })
    .catch((err) => {
      loadingEl.style.display = "none";
      contentEl.style.display = "block";
      schedulerEl.innerHTML = `<div class="text-danger">Failed to load system status: ${err.message}</div>`;
      notificationsEl.innerHTML = "";
      storageEl.innerHTML = "";
    });
}

function initSystemStatus() {
  const refreshBtn = document.getElementById("refresh-system-status-btn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", function () {
      loadSystemStatus();
    });
  }
}
