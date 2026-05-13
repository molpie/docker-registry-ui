// Analytics module
function loadAnalytics(registryName) {
  document.getElementById("analyticsTableBody").innerHTML =
    '<tr><td colspan="4" class="text-center"><div class="spinner-border spinner-border-sm"></div> Loading...</td></tr>';
  const riskTable = document.getElementById("riskRepoTableBody");
  if (riskTable) {
    riskTable.innerHTML =
      '<tr><td colspan="6" class="text-center"><div class="spinner-border spinner-border-sm"></div> Loading...</td></tr>';
  }

  fetch(`/api/analytics/${encodeURIComponent(registryName)}`)
    .then((r) => r.json())
    .then((data) => {
      document.getElementById("stat-total-repos").textContent = data.totalRepos;
      document.getElementById("stat-total-tags").textContent = data.totalTags;
      document.getElementById("stat-total-storage").textContent = formatSize(
        data.totalSize,
      );
      document.getElementById("stat-avg-size").textContent = formatSize(
        data.avgSize,
      );

      const vulnAnalytics = data.vulnerabilityAnalytics || {};
      const coverage = vulnAnalytics.coverage || {};
      const kpi = vulnAnalytics.kpi || {};
      const severityTotals = vulnAnalytics.severityTotals || {};
      const topRiskRepos = vulnAnalytics.topRiskRepos || [];

      document.getElementById("stat-scan-coverage").textContent =
        `${coverage.coveragePct || 0}%`;
      document.getElementById("stat-scan-coverage-details").textContent =
        `${coverage.scannedImages || 0}/${coverage.totalImages || 0} images`;
      document.getElementById("stat-total-vulns").textContent =
        kpi.totalVulnerabilities || 0;
      document.getElementById("stat-vuln-images").textContent =
        `${kpi.vulnerableImages || 0} vulnerable images`;
      document.getElementById("stat-images-critical").textContent =
        kpi.imagesWithCritical || 0;
      document.getElementById("stat-stale-scans").textContent =
        kpi.staleScansOver30Days || 0;

      let tableHtml = "";
      data.analytics.forEach((a) => {
        tableHtml += `<tr>
                    <td>${a.repo}</td>
                    <td>${a.tags}</td>
                    <td>${formatSize(a.size)}</td>
                    <td>${formatSize(a.avgSize)}</td>
                </tr>`;
      });
      document.getElementById("analyticsTableBody").innerHTML = tableHtml;

      const top10Size = data.analytics
        .sort((a, b) => b.size - a.size)
        .slice(0, 10);
      const top10Tags = data.analytics
        .sort((a, b) => b.tags - a.tags)
        .slice(0, 10);

      if (repoSizeChart) repoSizeChart.destroy();
      if (repoTagChart) repoTagChart.destroy();
      if (severityDistributionChart) severityDistributionChart.destroy();
      if (massiveScanTrendChart) massiveScanTrendChart.destroy();

      const ctx1 = document.getElementById("repoSizeChart").getContext("2d");
      repoSizeChart = new Chart(ctx1, {
        type: "bar",
        data: {
          labels: top10Size.map((a) => a.repo),
          datasets: [
            {
              label: "Size (MB)",
              data: top10Size.map((a) => (a.size / 1024 / 1024).toFixed(2)),
              backgroundColor: "rgba(13, 110, 253, 0.5)",
              borderColor: "rgba(13, 110, 253, 1)",
              borderWidth: 1,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          scales: { y: { beginAtZero: true } },
        },
      });

      const ctx2 = document.getElementById("repoTagChart").getContext("2d");
      repoTagChart = new Chart(ctx2, {
        type: "bar",
        data: {
          labels: top10Tags.map((a) => a.repo),
          datasets: [
            {
              label: "Tag Count",
              data: top10Tags.map((a) => a.tags),
              backgroundColor: "rgba(25, 135, 84, 0.5)",
              borderColor: "rgba(25, 135, 84, 1)",
              borderWidth: 1,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          scales: { y: { beginAtZero: true } },
        },
      });

      const severityCtx = document
        .getElementById("severityDistributionChart")
        .getContext("2d");
      severityDistributionChart = new Chart(severityCtx, {
        type: "doughnut",
        data: {
          labels: ["Critical", "High", "Medium", "Low", "Unknown"],
          datasets: [
            {
              data: [
                severityTotals.CRITICAL || 0,
                severityTotals.HIGH || 0,
                severityTotals.MEDIUM || 0,
                severityTotals.LOW || 0,
                severityTotals.UNKNOWN || 0,
              ],
              backgroundColor: [
                "rgba(220, 53, 69, 0.85)",
                "rgba(253, 126, 20, 0.85)",
                "rgba(13, 202, 240, 0.85)",
                "rgba(108, 117, 125, 0.85)",
                "rgba(173, 181, 189, 0.85)",
              ],
              borderColor: [
                "rgba(220, 53, 69, 1)",
                "rgba(253, 126, 20, 1)",
                "rgba(13, 202, 240, 1)",
                "rgba(108, 117, 125, 1)",
                "rgba(173, 181, 189, 1)",
              ],
              borderWidth: 1,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "bottom",
            },
          },
        },
      });

      let riskHtml = "";
      const topTen = topRiskRepos.slice(0, 10);
      topTen.forEach((repo) => {
        riskHtml += `<tr>
                    <td>${repo.repo}</td>
                    <td>${repo.scannedTags || 0}</td>
                    <td>${repo.vulnerableTags || 0}</td>
                    <td><span class="badge bg-danger">${repo.CRITICAL || 0}</span></td>
                    <td><span class="badge bg-warning text-dark">${repo.HIGH || 0}</span></td>
                    <td>${repo.total || 0}</td>
                </tr>`;
      });

      for (let i = topTen.length; i < 10; i++) {
        riskHtml += `<tr class="analytics-risk-filler-row">
                    <td>&nbsp;</td>
                    <td>&nbsp;</td>
                    <td>&nbsp;</td>
                    <td>&nbsp;</td>
                    <td>&nbsp;</td>
                    <td>&nbsp;</td>
                </tr>`;
      }

      document.getElementById("riskRepoTableBody").innerHTML =
        riskHtml ||
        '<tr><td colspan="6" class="text-center text-muted">No scan data available yet</td></tr>';

      const trend = (data.massiveScanTrend || []).slice().reverse();
      const trendCanvas = document.getElementById("massiveScanTrendChart");
      if (trendCanvas) {
        const trendCtx = trendCanvas.getContext("2d");
        const labels = trend.map((r) => {
          const dt = new Date(r.runAt || "");
          if (Number.isNaN(dt.getTime())) return r.runAt || "n/a";
          return dt.toLocaleString();
        });

        massiveScanTrendChart = new Chart(trendCtx, {
          type: "line",
          data: {
            labels,
            datasets: [
              {
                label: "Scans",
                data: trend.map((r) => r.totalScans || 0),
                borderColor: "rgba(13, 110, 253, 1)",
                backgroundColor: "rgba(13, 110, 253, 0.2)",
                tension: 0.2,
                yAxisID: "yScans",
              },
              {
                label: "Critical",
                data: trend.map((r) => r.critical || 0),
                borderColor: "rgba(220, 53, 69, 1)",
                backgroundColor: "rgba(220, 53, 69, 0.2)",
                tension: 0.2,
                yAxisID: "ySev",
              },
              {
                label: "High",
                data: trend.map((r) => r.high || 0),
                borderColor: "rgba(253, 126, 20, 1)",
                backgroundColor: "rgba(253, 126, 20, 0.2)",
                tension: 0.2,
                yAxisID: "ySev",
              },
              {
                label: "Medium",
                data: trend.map((r) => r.medium || 0),
                borderColor: "rgba(13, 202, 240, 1)",
                backgroundColor: "rgba(13, 202, 240, 0.2)",
                tension: 0.2,
                yAxisID: "ySev",
              },
              {
                label: "Low",
                data: trend.map((r) => r.low || 0),
                borderColor: "rgba(108, 117, 125, 1)",
                backgroundColor: "rgba(108, 117, 125, 0.2)",
                tension: 0.2,
                yAxisID: "ySev",
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
              mode: "index",
              intersect: false,
            },
            scales: {
              yScans: {
                type: "linear",
                position: "left",
                beginAtZero: true,
                title: { display: true, text: "Scans" },
              },
              ySev: {
                type: "linear",
                position: "right",
                beginAtZero: true,
                grid: { drawOnChartArea: false },
                title: { display: true, text: "Vulnerabilities" },
              },
            },
          },
        });
      }
    });
}
