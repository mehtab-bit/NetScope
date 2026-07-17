document.addEventListener("DOMContentLoaded", () => {
    // State management
    let activeFlows = [];
    let chatHistory = [];
    let savedApiKey = localStorage.getItem("gemini_api_key") || "";
    let searchTimeout = null;
    
    // UI Elements
    const sidebar = document.getElementById("sidebar");
    const hamburgerBtn = document.getElementById("hamburgerBtn");
    const closeSidebarBtn = document.getElementById("closeSidebarBtn");
    const newAnalysisBtn = document.getElementById("newAnalysisBtn");
    const exportCsvBtn = document.getElementById("exportCsvBtn");
    const onboardingModal = document.getElementById("onboardingModal");
    const onboardingDismissBtn = document.getElementById("onboardingDismissBtn");
    
    const apiKeyInput = document.getElementById("apiKeyInput");
    const saveKeyBtn = document.getElementById("saveKeyBtn");
    const keyStatus = document.getElementById("keyStatus");
    const demoList = document.getElementById("demoList");
    const uploadArea = document.getElementById("uploadArea");
    const pcapFileInput = document.getElementById("pcapFile");
    const loadingOverlay = document.getElementById("loadingOverlay");
    const loaderMessage = document.getElementById("loaderMessage");
    const dashboardView = document.getElementById("dashboardView");
    const activeFileIndicator = document.getElementById("activeFileIndicator");
    
    // Metrics Elements
    const metricPackets = document.getElementById("metricPackets");
    const metricFlows = document.getElementById("metricFlows");
    const metricVolume = document.getElementById("metricVolume");
    const metricThreats = document.getElementById("metricThreats");
    const threatCard = document.getElementById("threatCard");
    const threatIcon = document.getElementById("threatIcon");
    const threatLabel = document.getElementById("threatLabel");
    
    // Dashboard Core Panels
    const insightContent = document.getElementById("insightContent");
    const protocolChart = document.getElementById("protocolChart");
    const appChart = document.getElementById("appChart");
    const flowTableBody = document.getElementById("flowTableBody");
    const flowSearch = document.getElementById("flowSearch");
    const regenerateInsightBtn = document.getElementById("regenerateInsightBtn");
    
    // Chat Elements
    const chatWidget = document.getElementById("chatWidget");
    const chatTrigger = document.getElementById("chatTrigger");
    const chatBody = document.getElementById("chatBody");
    const chatInput = document.getElementById("chatInput");
    const sendChatBtn = document.getElementById("sendChatBtn");
    const chatSuggestions = document.getElementById("chatSuggestions");
    const minimizeChatBtn = document.getElementById("minimizeChatBtn");
    const chatBadge = document.getElementById("chatBadge");

    // Onboarding Modal Trigger
    if (!localStorage.getItem("onboarding_done")) {
        onboardingModal.style.display = "flex";
    }
    
    onboardingDismissBtn.addEventListener("click", () => {
        localStorage.setItem("onboarding_done", "true");
        onboardingModal.style.display = "none";
        showToast("Welcome! Try dragging a PCAP file or running a demo.", "success");
    });

    // Mobile Sidebar controls
    hamburgerBtn.addEventListener("click", () => {
        sidebar.classList.add("open");
    });

    closeSidebarBtn.addEventListener("click", () => {
        sidebar.classList.remove("open");
    });

    // Close sidebar on outside click on mobile
    document.addEventListener("click", (e) => {
        if (window.innerWidth <= 1024) {
            if (!sidebar.contains(e.target) && !hamburgerBtn.contains(e.target) && sidebar.classList.contains("open")) {
                sidebar.classList.remove("open");
            }
        }
    });

    // Initialize API Key view
    if (savedApiKey) {
        apiKeyInput.value = savedApiKey;
        updateKeyStatus(true);
    } else {
        updateKeyStatus(false);
    }
    
    // Load Demo Options
    loadDemos();

    // Event Listeners
    saveKeyBtn.addEventListener("click", () => {
        const val = apiKeyInput.value.trim();
        if (val) {
            localStorage.setItem("gemini_api_key", val);
            savedApiKey = val;
            updateKeyStatus(true);
            showToast("Gemini API Key configured locally!", "success");
        } else {
            localStorage.removeItem("gemini_api_key");
            savedApiKey = "";
            updateKeyStatus(false);
            showToast("API Key cleared.", "success");
        }
    });

    // File Drag & Drop
    uploadArea.addEventListener("dragover", (e) => {
        e.preventDefault();
        uploadArea.classList.add("dragover");
    });
    
    uploadArea.addEventListener("dragleave", () => {
        uploadArea.classList.remove("dragover");
    });
    
    uploadArea.addEventListener("drop", (e) => {
        e.preventDefault();
        uploadArea.classList.remove("dragover");
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });

    pcapFileInput.addEventListener("change", (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });

    // Reset View Trigger
    newAnalysisBtn.addEventListener("click", () => {
        resetToUploadView();
    });

    // CSV Export trigger
    exportCsvBtn.addEventListener("click", () => {
        exportFlowsToCsv();
    });

    // Debounced Filtering Table
    flowSearch.addEventListener("input", (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            filterFlowsTable(e.target.value);
        }, 150);
    });

    // AI Insight Regenerate
    regenerateInsightBtn.addEventListener("click", () => {
        if (activeFlows.length > 0) {
            insightContent.innerHTML = '<p class="loader"><i class="fa-solid fa-wand-magic-sparkles fa-spin"></i> Refreshing AI insights...</p>';
            runGeminiAnalysis(activeFlows);
        }
    });

    // Chat Window controls
    minimizeChatBtn.addEventListener("click", () => {
        chatWidget.style.display = "none";
        chatTrigger.style.display = "flex";
    });

    chatTrigger.addEventListener("click", () => {
        chatWidget.style.display = "flex";
        chatTrigger.style.display = "none";
        chatBadge.style.display = "none";
    });

    // Escape shortcut to minimize chat
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && chatWidget.style.display === "flex") {
            chatWidget.style.display = "none";
            chatTrigger.style.display = "flex";
        }
    });

    sendChatBtn.addEventListener("click", () => {
        sendChatMessage();
    });

    chatInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            sendChatMessage();
        }
    });

    // Suggestions chips
    chatSuggestions.addEventListener("click", (e) => {
        if (e.target.classList.contains("chip")) {
            chatInput.value = e.target.textContent;
            sendChatMessage();
        }
    });

    // functions
    function updateKeyStatus(configured) {
        if (configured) {
            keyStatus.className = "key-status status-configured";
            keyStatus.innerHTML = '<i class="fa-solid fa-circle-check"></i> Connected';
        } else {
            keyStatus.className = "key-status status-unconfigured";
            keyStatus.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Using Offline Mode';
        }
    }

    async function loadDemos() {
        try {
            const res = await fetch("/api/demos");
            const demos = await res.json();
            
            demoList.innerHTML = "";
            demos.forEach(demo => {
                const card = document.createElement("button");
                card.className = "demo-card";
                card.innerHTML = `
                    <h4>${demo.name}</h4>
                    <p>${demo.description}</p>
                `;
                card.addEventListener("click", () => loadDemoAnalysis(demo.id));
                demoList.appendChild(card);
            });
        } catch (e) {
            demoList.innerHTML = '<p class="error-msg">Failed to load demos.</p>';
        }
    }

    async function loadDemoAnalysis(demoId) {
        showLoading("Loading Demo Capture", "Retrieving preloaded network trace packets and running packet inspection...");
        try {
            const res = await fetch(`/api/analyze-demo/${demoId}`, { method: "POST" });
            if (!res.ok) throw new Error(await res.text());
            const data = await res.json();
            renderDashboard(data);
        } catch (e) {
            hideLoading();
            showToast(`Error loading demo: ${e.message}`, "error");
        }
    }

    async function handleFileUpload(file) {
        const formData = new FormData();
        formData.append("file", file);

        showLoading("Uploading & Inspecting", "Transferring file to server, running DPI protocol extraction, and mapping flow metrics...");
        try {
            const res = await fetch("/api/upload", {
                method: "POST",
                body: formData
            });
            if (!res.ok) throw new Error(await res.text());
            const data = await res.json();
            renderDashboard(data);
        } catch (e) {
            hideLoading();
            showToast(`Upload failed: ${e.message}`, "error");
        }
    }

    function showLoading(title, desc) {
        loadingOverlay.style.display = "flex";
        loaderMessage.innerHTML = `<strong>${title}</strong><br/>${desc}`;
    }

    function hideLoading() {
        loadingOverlay.style.display = "none";
    }

    function renderDashboard(data) {
        hideLoading();
        
        // Update file indicator
        activeFileIndicator.innerHTML = `<span class="pulse" style="background:#38ef7d;"></span> Analyzed: ${data.filename}`;
        
        // Show viewports
        uploadArea.style.display = "none";
        dashboardView.style.display = "flex";
        chatWidget.style.display = "flex";
        chatTrigger.style.display = "none";
        newAnalysisBtn.style.display = "block";

        activeFlows = data.flows;
        chatHistory = [];
        
        // Clear chat
        chatBody.innerHTML = `
            <div class="chat-message bot">
                <div class="message-bubble">
                    Hello! I have completed analyzing **${data.filename}**. Ask me any questions about the protocols, IP addresses, or threats found!
                </div>
            </div>
        `;
        
        // Render stats
        animateCounter(metricPackets, data.packets_count);
        animateCounter(metricFlows, data.flows_count);
        
        // Volume calculation
        let bytes = 0;
        data.flows.forEach(f => bytes += f.byte_count);
        if (bytes > 1024 * 1024) {
            metricVolume.textContent = `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
        } else {
            metricVolume.textContent = `${(bytes / 1024).toFixed(1)} KB`;
        }

        // Threats calculation
        let threatCount = 0;
        data.flows.forEach(f => {
            if (f.anomalies && f.anomalies.length > 0) threatCount++;
        });
        
        metricThreats.textContent = threatCount;
        if (threatCount > 0) {
            threatCard.classList.add("bg-red");
            threatIcon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
            threatLabel.textContent = "Security Warnings";
            threatIcon.style.color = "white";
        } else {
            threatCard.className = "metric-card";
            threatIcon.innerHTML = '<i class="fa-solid fa-shield-halved"></i>';
            threatLabel.textContent = "Threats Identified";
            threatIcon.style.color = "";
        }

        // Render charts
        renderCharts(data.flows);

        // Populate Table
        populateFlowsTable(data.flows);

        // Run animations
        setupScrollAnimations();

        // Call Gemini for plain English summary
        insightContent.innerHTML = '<p class="loader"><i class="fa-solid fa-wand-magic-sparkles fa-spin"></i> Formulating AI trace summary...</p>';
        runGeminiAnalysis(data.flows);
    }

    function animateCounter(element, target) {
        let current = 0;
        const duration = 1000; // 1s animation
        const stepTime = Math.abs(Math.floor(duration / target));
        const increment = Math.ceil(target / 40);
        
        const timer = setInterval(() => {
            current += increment;
            if (current >= target) {
                element.textContent = target.toLocaleString();
                clearInterval(timer);
            } else {
                element.textContent = current.toLocaleString();
            }
        }, 20);
    }

    function renderCharts(flows) {
        // Calculate Protocol split
        const protoCounts = {};
        const appCounts = {};
        let maxProto = 0;
        let maxApp = 0;

        flows.forEach(f => {
            protoCounts[f.protocol] = (protoCounts[f.protocol] || 0) + f.byte_count;
            appCounts[f.app_category] = (appCounts[f.app_category] || 0) + f.byte_count;
        });

        Object.values(protoCounts).forEach(v => { if (v > maxProto) maxProto = v; });
        Object.values(appCounts).forEach(v => { if (v > maxApp) maxApp = v; });

        // Protocol UI Chart
        protocolChart.innerHTML = "";
        Object.entries(protoCounts).sort((a,b) => b[1] - a[1]).forEach(([proto, bytes]) => {
            const pct = maxProto > 0 ? (bytes / maxProto) * 100 : 0;
            const sizeStr = bytes > 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)}MB` : `${(bytes / 1024).toFixed(1)}KB`;
            
            const row = document.createElement("div");
            row.className = "chart-row";
            row.innerHTML = `
                <span class="chart-label">${proto}</span>
                <div class="chart-track">
                    <div class="chart-fill" style="width: 0%; background: linear-gradient(90deg, #4776e6, #8e54e9)"></div>
                </div>
                <span class="chart-val">${sizeStr}</span>
            `;
            protocolChart.appendChild(row);
            setTimeout(() => {
                row.querySelector(".chart-fill").style.width = `${pct}%`;
            }, 100);
        });

        // App Categories UI Chart
        appChart.innerHTML = "";
        Object.entries(appCounts).sort((a,b) => b[1] - a[1]).slice(0, 5).forEach(([app, bytes]) => {
            const pct = maxApp > 0 ? (bytes / maxApp) * 100 : 0;
            const sizeStr = bytes > 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)}MB` : `${(bytes / 1024).toFixed(1)}KB`;
            
            const row = document.createElement("div");
            row.className = "chart-row";
            row.innerHTML = `
                <span class="chart-label">${app}</span>
                <div class="chart-track">
                    <div class="chart-fill" style="width: 0%; background: linear-gradient(90deg, #8e54e9, #f857a6)"></div>
                </div>
                <span class="chart-val">${sizeStr}</span>
            `;
            appChart.appendChild(row);
            setTimeout(() => {
                row.querySelector(".chart-fill").style.width = `${pct}%`;
            }, 100);
        });
    }

    function populateFlowsTable(flows) {
        flowTableBody.innerHTML = "";
        flows.forEach(flow => {
            const tr = document.createElement("tr");
            tr.setAttribute("data-search", `${flow.src_ip} ${flow.dst_ip} ${flow.protocol} ${flow.app_category} ${flow.domain}`);
            
            // App category class mapping
            let catClass = "cat-unknown";
            const app = flow.app_category.toLowerCase();
            if (app.includes("youtube") || app.includes("netflix") || app.includes("streaming")) catClass = "cat-streaming";
            else if (app.includes("dns")) catClass = "cat-dns";
            else if (app.includes("web") || app.includes("google") || app.includes("facebook") || app.includes("instagram")) catClass = "cat-web";
            else if (app.includes("file") || app.includes("ftp") || app.includes("ssh")) catClass = "cat-file";
            else if (app.includes("threat") || app.includes("security")) catClass = "cat-threat";

            // Security Lock mapping
            let secHtml = '<i class="fa-solid fa-lock status-secure" title="Encrypted Connection"></i> Secure';
            if (!flow.is_secure) {
                secHtml = '<i class="fa-solid fa-lock-open status-unencrypted" title="Unencrypted Plaintext Data"></i> Plaintext';
            }
            if (flow.anomalies && flow.anomalies.length > 0) {
                secHtml = '<i class="fa-solid fa-circle-exclamation status-threat" title="Anomaly Flagged"></i> Warning';
                tr.style.background = "rgba(255, 88, 88, 0.04)";
            }

            const sizeStr = flow.byte_count > 1024 * 1024 ? `${(flow.byte_count / (1024*1024)).toFixed(2)} MB` : `${(flow.byte_count / 1024).toFixed(1)} KB`;

            tr.innerHTML = `
                <td><strong>#${flow.flow_id}</strong></td>
                <td><code>${flow.src_ip}</code></td>
                <td><code>${flow.dst_ip}</code></td>
                <td><span class="badge-proto">${flow.protocol}</span></td>
                <td><code>${flow.dst_port}</code></td>
                <td><span class="badge-category ${catClass}">${flow.app_category}</span></td>
                <td><span class="domain-text" title="${flow.domain}">${flow.domain || '-'}</span></td>
                <td>${sizeStr}</td>
                <td>${flow.packet_count}</td>
                <td>${secHtml}</td>
            `;
            flowTableBody.appendChild(tr);
        });
    }

    function filterFlowsTable(q) {
        const query = q.toLowerCase();
        const rows = flowTableBody.querySelectorAll("tr");
        rows.forEach(row => {
            const txt = row.getAttribute("data-search").toLowerCase();
            row.style.display = txt.includes(query) ? "" : "none";
        });
    }

    async function runGeminiAnalysis(flows) {
        try {
            insightContent.innerHTML = "";
            const res = await fetch("/api/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    flows: flows,
                    api_key: savedApiKey
                })
            });

            if (!res.ok) throw new Error(await res.text());
            
            // Read stream
            const reader = res.body.getReader();
            const decoder = new TextDecoder("utf-8");
            let buffer = "";
            let fullText = "";

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                
                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split("\n\n");
                buffer = lines.pop(); // keep last incomplete line
                
                for (const line of lines) {
                    if (line.startsWith("data: ")) {
                        const dataStr = line.substring(6).trim();
                        if (dataStr === "[DONE]") continue;
                        
                        try {
                            const data = JSON.parse(dataStr);
                            fullText += data.text;
                            insightContent.innerHTML = formatMarkdown(fullText);
                        } catch (err) {
                            // ignore json parse errors for non-json logs
                        }
                    }
                }
            }
        } catch (e) {
            insightContent.innerHTML = `<p class="error-msg">⚠️ AI Analysis failed: ${e.message}. Please check your connection or key status.</p>`;
        }
    }

    async function sendChatMessage() {
        const query = chatInput.value.trim();
        if (!query || activeFlows.length === 0) return;
        
        chatInput.value = "";
        
        // Render user message
        renderChatMessage("user", query);
        
        // Scroll to bottom
        chatBody.scrollTop = chatBody.scrollHeight;
        
        // Render bot thinking bubble
        const botMsgDiv = renderChatMessage("bot", '<div class="typing-indicator"><span></span><span></span><span></span></div>');
        const bubble = botMsgDiv.querySelector(".message-bubble");
        
        try {
            const res = await fetch("/api/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    flows: activeFlows,
                    user_query: query,
                    chat_history: chatHistory,
                    api_key: savedApiKey
                })
            });
            
            if (!res.ok) throw new Error(await res.text());
            
            // Parse Stream
            const reader = res.body.getReader();
            const decoder = new TextDecoder("utf-8");
            let buffer = "";
            let fullBotResponse = "";
            bubble.innerHTML = "";

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                
                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split("\n\n");
                buffer = lines.pop();
                
                for (const line of lines) {
                    if (line.startsWith("data: ")) {
                        const dataStr = line.substring(6).trim();
                        if (dataStr === "[DONE]") continue;
                        
                        try {
                            const data = JSON.parse(dataStr);
                            fullBotResponse += data.text;
                            bubble.innerHTML = formatMarkdown(fullBotResponse);
                            chatBody.scrollTop = chatBody.scrollHeight;
                        } catch (err) {}
                    }
                }
            }
            
            // Update history
            chatHistory.push({ role: "user", content: query });
            chatHistory.push({ role: "bot", content: fullBotResponse });
            
        } catch (e) {
            bubble.innerHTML = `<span class="status-threat">Error: ${e.message}</span>`;
        }
    }

    function renderChatMessage(sender, content) {
        const msg = document.createElement("div");
        msg.className = `chat-message ${sender}`;
        msg.innerHTML = `<div class="message-bubble">${content}</div>`;
        chatBody.appendChild(msg);
        return msg;
    }

    function showToast(message, type = "success") {
        const container = document.getElementById("toastContainer");
        if (!container) return;
        
        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        
        const iconClass = type === "success" ? "fa-circle-check" : "fa-circle-exclamation";
        toast.innerHTML = `
            <i class="fa-solid ${iconClass}"></i>
            <span>${message}</span>
        `;
        
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.animation = "toast-out 0.3s cubic-bezier(0.4, 0, 0.2, 1) forwards";
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    function resetToUploadView() {
        dashboardView.style.display = "none";
        chatWidget.style.display = "none";
        chatTrigger.style.display = "none";
        newAnalysisBtn.style.display = "none";
        uploadArea.style.display = "flex";
        activeFileIndicator.innerHTML = '<span class="pulse"></span> Ready to analyze';
        activeFlows = [];
        chatHistory = [];
        pcapFileInput.value = "";
        showToast("Reset view. Ready to analyze new packet captures.", "success");
    }

    function exportFlowsToCsv() {
        if (activeFlows.length === 0) {
            showToast("No active flows to export", "error");
            return;
        }
        
        let csv = "Flow ID,Source IP,Destination IP,Protocol,Dest Port,Category,Domain,Total Size (Bytes),Packets,Security Status\n";
        
        activeFlows.forEach(flow => {
            const sec = flow.anomalies && flow.anomalies.length > 0 ? "Warning" : (flow.is_secure ? "Secure" : "Plaintext");
            csv += `${flow.flow_id},${flow.src_ip},${flow.dst_ip},${flow.protocol},${flow.dst_port},"${flow.app_category}","${flow.domain || ""}",${flow.byte_count},${flow.packet_count},${sec}\n`;
        });
        
        const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.setAttribute("href", url);
        link.setAttribute("download", `netscope_flows_${Date.now()}.csv`);
        link.style.visibility = "hidden";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showToast("Flows exported as CSV successfully!", "success");
    }

    function setupScrollAnimations() {
        const cards = document.querySelectorAll(".metric-card, .glass-card");
        cards.forEach((card, index) => {
            card.classList.add("fade-in-on-scroll");
            card.style.transitionDelay = `${index * 0.05}s`;
        });

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add("visible");
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.05 });

        cards.forEach(card => observer.observe(card));
    }

    // Markdown Parser
    function formatMarkdown(text) {
        let html = text;
        
        // Escape HTML tags to prevent XSS but keep formatting
        html = html
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");

        // Restore alerts/blockquotes
        html = html
            .replace(/&gt; \[!NOTE\]\s*/gi, '<blockquote class="alert note"><strong>INFO:</strong> ')
            .replace(/&gt; \[!WARNING\]\s*/gi, '<blockquote class="alert warning"><strong>WARNING:</strong> ')
            .replace(/&gt; \[!IMPORTANT\]\s*/gi, '<blockquote class="alert important"><strong>IMPORTANT:</strong> ')
            .replace(/&gt;\s*(.*)/g, '<blockquote>$1</blockquote>');

        // Headers
        html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
        html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
        html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');
        
        // Bold
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        
        // Code blocks & inline code
        html = html.replace(/`(.*?)`/g, '<code>$1</code>');
        
        // Lists
        html = html.replace(/^\s*-\s+(.*)$/gim, '<li>$1</li>');
        html = html.replace(/(<li>.*<\/li>)/g, '<ul>$1</ul>');
        // clean multiple ul tags
        html = html.replace(/<\/ul>\s*<ul>/g, '');

        // Line breaks
        html = html.replace(/\n/g, '<br/>');
        
        return html;
    }
});
