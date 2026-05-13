function loadSystemStatus() {
  const loadingEl = document.getElementById("system-status-loading");
  const contentEl = document.getElementById("system-status-content");
  const schedulerEl = document.getElementById("scheduler-status-card");
  const notificationsEl = document.getElementById("notifications-status-card");
  const storageEl = document.getElementById("storage-status-card");

  if (
    !loadingEl ||
    !contentEl ||
    !schedulerEl ||
    !notificationsEl ||
    !storageEl
  ) {
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

      const formatDateTime = (value) => {
        if (!value) return "n/a";
        const dt = new Date(value);
        if (Number.isNaN(dt.getTime())) return value;
        return dt.toLocaleString();
      };

      const formatRunSummary = (title, summary) => {
        if (!summary) {
          return `
            <div class="mt-2">
              <strong>${title}:</strong>
              <div class="small text-muted">No data</div>
            </div>
          `;
        }

        return `
          <div class="mt-2 border rounded p-2">
            <div class="d-flex justify-content-between align-items-center mb-1">
              <strong>${title}</strong>
              <small class="text-muted">${formatDateTime(summary.runAt)}</small>
            </div>
            <div class="small">Source: <strong>${summary.source || "n/a"}</strong> ${summary.timezone ? `(${summary.timezone})` : ""}</div>
            <div class="small">Totals: images <strong>${summary.totalImages || 0}</strong>, tags <strong>${summary.totalTags || 0}</strong>, scans <strong>${summary.totalScans || 0}</strong></div>
            <div class="small">Severities: <span class="text-danger">C ${summary.critical || 0}</span> · <span class="text-warning">H ${summary.high || 0}</span> · <span class="text-info">M ${summary.medium || 0}</span> · <span class="text-secondary">L ${summary.low || 0}</span></div>
            <div class="small">Execution: scanned <strong>${summary.scanned || 0}</strong>, skipped <strong>${summary.skipped || 0}</strong>, errors <strong>${summary.errors || 0}</strong>, dry-run <strong>${summary.dryRun ? "yes" : "no"}</strong></div>
          </div>
        `;
      };

      schedulerEl.innerHTML = `
        <div class="mb-1"><strong>Enabled:</strong> ${scheduler.enabled ? "Yes" : "No"}</div>
        <div class="mb-1"><strong>Thread active:</strong> ${scheduler.threadActive ? "Yes" : "No"}</div>
        <div class="mb-1"><strong>Job in progress:</strong> ${scheduler.jobRunning ? "Yes" : "No"}</div>
        <div class="mb-1"><strong>Schedule:</strong> ${scheduler.scheduleTime || "N/A"} (${scheduler.timezone || "local"})</div>
        <div class="mb-1"><strong>Target registries:</strong> <code>${scheduler.targetRegistries || "all"}</code></div>
        <div class="mb-1"><strong>Mode:</strong> ${scheduler.mode || "all"}</div>
        <div class="mb-1"><strong>Repo pattern:</strong> <code>${scheduler.repoPattern || "*"}</code></div>
        <div class="mb-1"><strong>Include all tags:</strong> ${scheduler.includeAllTags ? "Yes" : "No"}</div>
        <div class="mb-1"><strong>Dry run:</strong> ${scheduler.dryRun ? "Yes" : "No"}</div>
        <div class="mb-1"><strong>Last run at:</strong> ${scheduler.lastRunAt ? formatDateTime(scheduler.lastRunAt) : "Never"}</div>
        <div class="mb-1"><strong>Last error:</strong> ${scheduler.lastError || "None"}</div>
        ${formatRunSummary("Current Run", scheduler.lastRunSummary)}
        ${formatRunSummary("Previous Run", scheduler.previousRunSummary)}
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
