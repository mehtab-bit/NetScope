import sys

file_path = r'd:\CS\Projects\Packet_analyzer\frontend\app.js'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

marker = r"html = html.replace(/<\/ul>\s*<ul>/g, '');"
idx = content.find(marker)

if idx == -1:
    print('Marker not found')
    sys.exit(1)

# Keep everything up to the marker + marker length
new_content = content[:idx + len(marker)]

new_content += """

        // Line breaks
        html = html.replace(/\\n/g, '<br/>');
        
        return html;
    }
    
    // ============================================
    // DPI ENGINE INTEGRATION
    // ============================================
    let dpiRules = [];
    const dpiRuleType = document.getElementById("dpiRuleType");
    const dpiRuleValue = document.getElementById("dpiRuleValue");
    const dpiAddRuleBtn = document.getElementById("dpiAddRuleBtn");
    const dpiRulesList = document.getElementById("dpiRulesList");
    const dpiRunBtn = document.getElementById("dpiRunBtn");
    const dpiDownloadBtn = document.getElementById("dpiDownloadBtn");
    const dpiResults = document.getElementById("dpiResults");

    if (dpiAddRuleBtn) {
        dpiAddRuleBtn.addEventListener("click", () => {
            const type = dpiRuleType.value;
            const value = dpiRuleValue.value.trim();
            if (!value) {
                showToast("Enter a value for the rule.", "error");
                return;
            }
            dpiRules.push({ type, value });
            dpiRuleValue.value = "";
            renderDpiRules();
        });
    }

    if (dpiRunBtn) {
        dpiRunBtn.addEventListener("click", async () => {
            if (dpiRules.length === 0) {
                showToast("Add at least one blocking rule before running.", "error");
                return;
            }
            if (activeFlows.length === 0) {
                showToast("No capture loaded. Upload a PCAP first.", "error");
                return;
            }

            dpiRunBtn.disabled = true;
            dpiRunBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Running...';

            try {
                const res = await fetch("/api/dpi/run", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ rules: dpiRules })
                });
                if (!res.ok) {
                    const errData = await res.json();
                    throw new Error(errData.detail || "DPI engine failed");
                }
                const data = await res.json();
                renderDpiResults(data);
                showToast("DPI engine completed successfully!", "success");
            } catch (e) {
                showToast(`DPI Error: ${e.message}`, "error");
                dpiResults.style.display = "none";
            } finally {
                dpiRunBtn.disabled = false;
                dpiRunBtn.innerHTML = '<i class="fa-solid fa-bolt"></i> Run DPI Engine';
            }
        });
    }

    function renderDpiRules() {
        dpiRulesList.innerHTML = "";
        dpiRules.forEach((rule, idx) => {
            const item = document.createElement("div");
            item.className = "dpi-rule-item";
            item.innerHTML = `
                <code>${rule.type} ${rule.value}</code>
                <button title="Remove" data-idx="${idx}"><i class="fa-solid fa-xmark"></i></button>
            `;
            item.querySelector("button").addEventListener("click", () => {
                dpiRules.splice(idx, 1);
                renderDpiRules();
            });
            dpiRulesList.appendChild(item);
        });
    }

    function renderDpiResults(data) {
        dpiResults.style.display = "block";
        dpiResults.innerHTML = `
            <div class="stat-line"><span>Total Packets</span><span class="stat-value">${data.total_packets}</span></div>
            <div class="stat-line"><span>Forwarded</span><span class="stat-value">${data.forwarded}</span></div>
            <div class="stat-line"><span>Dropped</span><span class="stat-value stat-dropped">${data.dropped}</span></div>
            <div class="stat-line"><span>Active Flows</span><span class="stat-value">${data.active_flows}</span></div>
        `;
        if (data.app_breakdown && Object.keys(data.app_breakdown).length > 0) {
            dpiResults.innerHTML += '<hr style="border-color:#2a2d3e;margin:6px 0;">';
            for (const [app, count] of Object.entries(data.app_breakdown)) {
                dpiResults.innerHTML += `<div class="stat-line"><span>${app}</span><span class="stat-value">${count} pkts</span></div>`;
            }
        }
        if (data.output_file) {
            dpiDownloadBtn.style.display = "inline-flex";
        }
    }

    if (dpiDownloadBtn) {
        dpiDownloadBtn.addEventListener("click", async () => {
            try {
                const res = await fetch("/api/dpi/download");
                if (!res.ok) throw new Error("Download failed");
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const link = document.createElement("a");
                link.href = url;
                link.download = "filtered_output.pcap";
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                showToast("Filtered PCAP downloaded.", "success");
            } catch (e) {
                showToast(`Download failed: ${e.message}`, "error");
            }
        });
    }
});
"""

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(new_content)
print("app.js fixed")
