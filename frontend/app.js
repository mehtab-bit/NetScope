document.addEventListener("DOMContentLoaded", () => {
    // State management
    let activeFlows = [];
    let activeGeoIpData = [];
    let chatHistory = [];
    let searchTimeout = null;
    let topologyAnimationId = null;
    let activeFilter = "all";
    
    // UI Elements
    const sidebar = document.getElementById("sidebar");
    const hamburgerBtn = document.getElementById("hamburgerBtn");
    const closeSidebarBtn = document.getElementById("closeSidebarBtn");
    const newAnalysisBtn = document.getElementById("newAnalysisBtn");
    const exportReportBtn = document.getElementById("exportReportBtn");
    const exportCsvBtn = document.getElementById("exportCsvBtn");
    const onboardingModal = document.getElementById("onboardingModal");
    const onboardingDismissBtn = document.getElementById("onboardingDismissBtn");
    
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
    const metricThreats = document.getElementById("metricMalicious");
    const threatCard = document.getElementById("threatCard");
    const threatIcon = document.getElementById("threatIcon");
    const threatLabel = null; // No longer present in index.html
    
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

    // Drawer Elements
    const inspectorDrawer = document.getElementById("inspectorDrawer");
    const closeDrawerBtn = document.getElementById("closeDrawerBtn");
    const drawerFlowTitle = document.getElementById("drawerFlowTitle");
    const drawerFlowSub = document.getElementById("drawerFlowSub");
    const drawerPacketBody = document.getElementById("drawerPacketBody");
    const hexViewer = document.getElementById("hexViewer");
    const tabBtnPackets = document.getElementById("tabBtnPackets");
    const tabBtnHex = document.getElementById("tabBtnHex");
    const tabFlowPackets = document.getElementById("tabFlowPackets");
    const tabFlowHex = document.getElementById("tabFlowHex");
    const tableFilters = document.getElementById("tableFilters");

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

    // Initialize API Key status checking (HTTP-Only Cookie/Server Env)
    checkKeyStatus();
    
    // Load Demo Options
    loadDemos();

    // Event Listeners

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

    newAnalysisBtn.addEventListener("click", () => {
        resetToUploadView();
    });

    if (exportReportBtn) {
        exportReportBtn.addEventListener("click", () => {
            window.open("/api/export-report", "_blank");
        });
    }

    // CSV Export trigger
    exportCsvBtn.addEventListener("click", () => {
        if (tabGeo && tabGeo.style.display === "block") {
            exportGeoIpToCsv();
        } else {
            exportFlowsToCsv();
        }
    });

    // Debounced Filtering Table
    flowSearch.addEventListener("input", (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            applyActiveFilters();
        }, 150);
    });

    // Close Drawer Bindings
    closeDrawerBtn.addEventListener("click", () => {
        inspectorDrawer.classList.remove("open");
    });

    tabBtnPackets.addEventListener("click", () => switchTab("flowPackets"));
    tabBtnHex.addEventListener("click", () => switchTab("flowHex"));

    // AI Insight Regenerate
    regenerateInsightBtn.addEventListener("click", () => {
        if (activeFlows.length > 0) {
            insightContent.innerHTML = '<p><i class="fa-solid fa-spinner fa-spin"></i> Refreshing analysis...</p>';
            runGeminiAnalysis(activeFlows);
        }
    });

    // Chat Window controls
    const chatHeader = document.getElementById("chatHeader");
    if (chatHeader) {
        chatHeader.addEventListener("click", () => {
            chatWidget.style.display = "none";
            chatTrigger.style.display = "flex";
        });
    }

    if (minimizeChatBtn) {
        minimizeChatBtn.addEventListener("click", (e) => {
            e.stopPropagation(); // Prevent duplicate trigger from chatHeader
            chatWidget.style.display = "none";
            chatTrigger.style.display = "flex";
        });
    }

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
            keyStatus.innerHTML = '<i class="fa-solid fa-circle-check"></i> AI Agent Active';
        } else {
            keyStatus.className = "key-status status-unconfigured";
            keyStatus.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Using Offline Mode';
        }
    }

    async function checkKeyStatus() {
        try {
            const res = await fetch("/api/config/status");
            const data = await res.json();
            updateKeyStatus(data.configured);
        } catch (e) {
            updateKeyStatus(false);
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

    function renderDashboard(data, skipGemini = false) {
        hideLoading();
        
        // Update file indicator
        activeFileIndicator.innerHTML = `<span class="pulse"></span> ${data.filename}`;
        
        // Show viewports
        uploadArea.style.display = "none";
        dashboardView.style.display = "flex";
        chatWidget.style.display = "flex";
        chatTrigger.style.display = "none";
        newAnalysisBtn.style.display = "block";
        if (exportReportBtn) exportReportBtn.style.display = "block";

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
        if (metricVolume) {
            if (bytes > 1024 * 1024) {
                metricVolume.textContent = `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
            } else {
                metricVolume.textContent = `${(bytes / 1024).toFixed(1)} KB`;
            }
        }

        // Threats calculation
        let threatCount = 0;
        data.flows.forEach(f => {
            if (f.anomalies && f.anomalies.length > 0) threatCount++;
        });
        
        if (metricThreats) {
            metricThreats.textContent = threatCount;
        }
        if (threatIcon) {
            if (threatCount > 0) {
                threatIcon.className = "metric-icon bg-red";
                threatIcon.innerHTML = '<i class="fa-solid fa-shield-virus"></i>';
            } else {
                threatIcon.className = "metric-icon bg-green";
                threatIcon.innerHTML = '<i class="fa-solid fa-shield-halved"></i>';
            }
        }
        if (threatLabel) {
            threatLabel.textContent = "Threats";
        }

        // Render charts
        renderCharts(data.flows);

        // Render bandwidth timeline line chart
        renderBandwidthTimeline(data.packets);
        
        // Render packets drill down modal table
        renderPacketTable(data.packets);

        // Initialize Topology Canvas Map
        initTopology(data.flows);

        // Populate Table
        populateFlowsTable(data.flows);

        // Run animations
        setupScrollAnimations();

        // Call AI for analysis report
        if (!skipGemini) {
            insightContent.innerHTML = '<p><i class="fa-solid fa-spinner fa-spin"></i> Generating analysis...</p>';
            runGeminiAnalysis(data.flows);
        } else {
            insightContent.innerHTML = `
                <div class="ai-stale-notice" style="padding: 1.25rem; border: 1px dashed var(--border-card); border-radius: var(--radius-lg); text-align: center; background: rgba(245,158,11,0.04); margin-bottom: 1rem;">
                    <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 8px;"><i class="fa-solid fa-circle-info" style="color: #f59e0b; margin-right: 6px;"></i> View updated dashboard metrics above. AI Analysis is still based on the original capture.</p>
                    <button class="btn-secondary btn-small" id="regenerateInsightBtnFiltered"><i class="fa-solid fa-rotate-right"></i> Run AI Analysis on Filtered Capture</button>
                </div>
            `;
            const filterRegenBtn = document.getElementById("regenerateInsightBtnFiltered");
            if (filterRegenBtn) {
                filterRegenBtn.addEventListener("click", () => {
                    insightContent.innerHTML = '<p><i class="fa-solid fa-spinner fa-spin"></i> Generating analysis...</p>';
                    runGeminiAnalysis(data.flows);
                });
            }
        }
    }

    function animateCounter(element, target) {
        if (!element) return;
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
            const fillClass = proto === "TCP" ? "proto-tcp" : proto === "UDP" ? "proto-udp" : "proto-other";
            
            const row = document.createElement("div");
            row.className = "bar-row";
            row.innerHTML = `
                <span class="bar-label">${proto}</span>
                <div class="bar-track">
                    <div class="bar-fill ${fillClass}" style="width: 0%"></div>
                </div>
                <span class="bar-value">${sizeStr}</span>
            `;
            protocolChart.appendChild(row);
            setTimeout(() => {
                row.querySelector(".bar-fill").style.width = `${pct}%`;
            }, 100);
        });

        // App Categories UI Chart
        appChart.innerHTML = "";
        Object.entries(appCounts).sort((a,b) => b[1] - a[1]).slice(0, 5).forEach(([app, bytes]) => {
            const pct = maxApp > 0 ? (bytes / maxApp) * 100 : 0;
            const sizeStr = bytes > 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)}MB` : `${(bytes / 1024).toFixed(1)}KB`;
            
            const row = document.createElement("div");
            row.className = "bar-row";
            row.innerHTML = `
                <span class="bar-label">${app}</span>
                <div class="bar-track">
                    <div class="bar-fill app-fill" style="width: 0%"></div>
                </div>
                <span class="bar-value">${sizeStr}</span>
            `;
            appChart.appendChild(row);
            setTimeout(() => {
                row.querySelector(".bar-fill").style.width = `${pct}%`;
            }, 100);
        });
    }

    // Canvas topology particle configurations
    let topologyNodes = [];
    let topologyLinks = [];
    let topologyParticles = [];

    function initTopology(flows) {
        if (topologyAnimationId) {
            cancelAnimationFrame(topologyAnimationId);
        }

        const canvas = document.getElementById("topologyCanvas");
        if (!canvas) return;
        const ctx = canvas.getContext("2d");

        // Fit canvas to parent node
        const rect = canvas.parentNode.getBoundingClientRect();
        canvas.width = rect.width || 550;
        canvas.height = rect.height || 240;

        const width = canvas.width;
        const height = canvas.height;

        topologyNodes = [];
        topologyLinks = [];
        topologyParticles = [];

        // 1. Center node representing Local Host Client
        const centerNode = {
            id: "local_host",
            label: "Local Client",
            ip: "192.168.1.100",
            x: width / 2,
            y: height / 2,
            size: 13,
            color: "#22d3ee",
            isCenter: true
        };
        topologyNodes.push(centerNode);

        // 2. Select top orbiting flows
        const externalIPMap = {};
        flows.forEach(flow => {
            const extIP = flow.dst_ip === "192.168.1.100" ? flow.src_ip : flow.dst_ip;
            if (extIP !== "192.168.1.100") {
                externalIPMap[extIP] = flow;
            }
        });

        const externalIPs = Object.values(externalIPMap).slice(0, 6);
        const maxBytes = Math.max(...externalIPs.map(f => f.byte_count), 1);
        
        externalIPs.forEach((flow, index) => {
            const angle = (index / externalIPs.length) * Math.PI * 2;
            const radius = Math.min(width, height) * 0.36;
            const x = width / 2 + Math.cos(angle) * radius;
            const y = height / 2 + Math.sin(angle) * radius;

            let color = "#60a5fa";
            if (flow.anomalies && flow.anomalies.length > 0) {
                color = "#f87171";
            } else if (flow.protocol === "DNS") {
                color = "#a78bfa";
            }

            const label = flow.app_category !== "UNKNOWN" ? flow.app_category : flow.domain || flow.dst_ip;
            const size = 5 + (flow.byte_count / maxBytes) * 10; // Sizes between 5px and 15px

            const node = {
                id: `node_${index}`,
                label: label,
                ip: flow.dst_ip === "192.168.1.100" ? flow.src_ip : flow.dst_ip,
                x: x,
                y: y,
                size: size,
                color: color,
                isCenter: false
            };
            topologyNodes.push(node);

            topologyLinks.push({
                source: centerNode,
                target: node,
                color: "rgba(255, 255, 255, 0.08)"
            });

            // Particles flowing along links
            const pCount = Math.min(Math.max(Math.floor(flow.packet_count / 10), 1), 6);
            for (let i = 0; i < pCount; i++) {
                const speed = 0.002 + (flow.packet_count / 1000) * 0.01 + Math.random() * 0.003;
                topologyParticles.push({
                    source: centerNode,
                    target: node,
                    progress: Math.random(),
                    speed: Math.min(Math.max(speed, 0.002), 0.015), // Bound speed
                    size: 1.5 + Math.random() * 2,
                    color: color
                });
            }
        });

        animateTopology(canvas, ctx);
    }

    function animateTopology(canvas, ctx) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        const isLight = document.body.classList.contains("light-theme");
        const linkColor = isLight ? "rgba(0, 0, 0, 0.08)" : "rgba(255, 255, 255, 0.08)";
        const nodeStrokeColor = isLight ? "rgba(0, 0, 0, 0.15)" : "rgba(255, 255, 255, 0.2)";
        const labelColor = isLight ? "#475569" : "#a0aec0";

        // Draw Links
        topologyLinks.forEach(link => {
            ctx.beginPath();
            ctx.moveTo(link.source.x, link.source.y);
            ctx.lineTo(link.target.x, link.target.y);
            ctx.strokeStyle = linkColor;
            ctx.lineWidth = 1;
            ctx.stroke();
        });

        // Draw Particles
        topologyParticles.forEach(p => {
            p.progress += p.speed;
            if (p.progress >= 1.0) p.progress = 0;

            const x = p.source.x + (p.target.x - p.source.x) * p.progress;
            const y = p.source.y + (p.target.y - p.source.y) * p.progress;

            ctx.beginPath();
            ctx.arc(x, y, p.size, 0, Math.PI * 2);
            ctx.fillStyle = p.color;
            ctx.globalAlpha = 0.7;
            ctx.fill();
            ctx.globalAlpha = 1.0;

        });

        // Draw Nodes
        topologyNodes.forEach(node => {
            if (node.isCenter) {
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.size + 4, 0, Math.PI * 2);
                ctx.fillStyle = isLight ? "rgba(2, 132, 199, 0.08)" : "rgba(34, 211, 238, 0.08)";
                ctx.fill();
            }

            ctx.beginPath();
            ctx.arc(node.x, node.y, node.size, 0, Math.PI * 2);
            ctx.fillStyle = node.color;
            ctx.fill();
            ctx.lineWidth = 1;
            ctx.strokeStyle = nodeStrokeColor;
            ctx.stroke();

            // Label text
            ctx.font = "10px Outfit, sans-serif";
            ctx.fillStyle = labelColor;
            ctx.textAlign = "center";
            ctx.fillText(node.label, node.x, node.y + node.size + 11);
        });

        topologyAnimationId = requestAnimationFrame(() => animateTopology(canvas, ctx));
    }

    function populateFlowsTable(flows) {
        flowTableBody.innerHTML = "";
        flows.forEach(flow => {
            const tr = document.createElement("tr");
            tr.setAttribute("data-search", `${flow.src_ip} ${flow.dst_ip} ${flow.protocol} ${flow.app_category} ${flow.domain}`);
            tr.style.cursor = "pointer";
            
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
                tr.style.background = "rgba(248, 113, 113, 0.04)";
            }

            const sizeStr = flow.byte_count > 1024 * 1024 ? `${(flow.byte_count / (1024*1024)).toFixed(2)} MB` : `${(flow.byte_count / 1024).toFixed(1)} KB`;

            // ML prediction confidence badge
            let confidenceBadge = "";
            if (flow.ml_confidence < 1.0) {
                confidenceBadge = `<span class="badge-confidence" title="Random Forest prediction probability">${Math.round(flow.ml_confidence * 100)}% ML</span>`;
            }

            tr.innerHTML = `
                <td><strong>#${flow.flow_id}</strong></td>
                <td><code>${flow.src_ip}</code></td>
                <td><code>${flow.dst_ip}</code></td>
                <td><span class="badge-proto">${flow.protocol}</span></td>
                <td><code>${flow.dst_port}</code></td>
                <td><span class="badge-category ${catClass}">${flow.app_category}${confidenceBadge}</span></td>
                <td><span class="domain-text" title="${flow.domain}">${flow.domain || '-'}</span></td>
                <td>${sizeStr}</td>
                <td>${flow.packet_count}</td>
                <td>${secHtml}</td>
            `;

            // Click listener for details drawer
            tr.addEventListener("click", () => {
                openInspectorDrawer(flow);
            });

            flowTableBody.appendChild(tr);
        });

        // Initialize / reset Filter Pills to All
        const filterPills = tableFilters.querySelectorAll(".filter-pill");
        filterPills.forEach(p => p.classList.remove("active"));
        tableFilters.querySelector('[data-filter="all"]').classList.add("active");
        activeFilter = "all";
    }

    // Category pills click handler binding
    const filterPills = tableFilters.querySelectorAll(".filter-pill");
    filterPills.forEach(pill => {
        pill.addEventListener("click", () => {
            filterPills.forEach(p => p.classList.remove("active"));
            pill.classList.add("active");
            activeFilter = pill.getAttribute("data-filter");
            applyActiveFilters();
        });
    });

    function applyActiveFilters() {
        const query = flowSearch.value.trim().toLowerCase();
        const rows = flowTableBody.querySelectorAll("tr");

        rows.forEach(row => {
            const searchTxt = row.getAttribute("data-search").toLowerCase();
            const proto = row.querySelector(".badge-proto").textContent;
            const category = row.querySelector(".badge-category").textContent.toLowerCase();
            const securityCell = row.innerHTML.toLowerCase();

            const matchesSearch = searchTxt.includes(query);
            
            let matchesFilter = true;
            if (activeFilter === "TCP") {
                matchesFilter = (proto === "TCP");
            } else if (activeFilter === "UDP") {
                matchesFilter = (proto === "UDP");
            } else if (activeFilter === "DNS") {
                matchesFilter = (category.includes("dns") || searchTxt.includes("dns"));
            } else if (activeFilter === "threat") {
                matchesFilter = (securityCell.includes("warning") || securityCell.includes("status-threat") || category.includes("threat"));
            }

            row.style.display = (matchesSearch && matchesFilter) ? "" : "none";
        });
    }

    // Slide open details drawer
    async function openInspectorDrawer(flow) {
        inspectorDrawer.classList.add("open");
        
        drawerFlowTitle.textContent = `Flow Conversation #${flow.flow_id}`;
        drawerFlowSub.textContent = `${flow.src_ip}:${flow.src_port} ➔ ${flow.dst_ip}:${flow.dst_port} (${flow.protocol})`;
        
        switchTab("flowPackets");
        
        drawerPacketBody.innerHTML = '<tr><td colspan="4" style="text-align:center;"><i class="fa-solid fa-spinner fa-spin"></i> Loading packets...</td></tr>';
        hexViewer.innerHTML = '<div class="hex-empty-state">No packet selected. Select a packet from the "Packet List" tab first.</div>';

        try {
            const res = await fetch(`/api/flow-packets/${flow.flow_id}`);
            if (!res.ok) throw new Error(await res.text());
            const data = await res.json();
            
            drawerPacketBody.innerHTML = "";
            if (!data.packets || data.packets.length === 0) {
                drawerPacketBody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted);">No detailed packets captured for this flow.</td></tr>';
                return;
            }

            data.packets.forEach(pkt => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td><strong>#${pkt.packet_id}</strong></td>
                    <td>${pkt.length} B</td>
                    <td><code>${pkt.tcp_flags || "-"}</code></td>
                    <td><span class="info-cell">${pkt.sni || pkt.http_host || pkt.dns_query || "Data Payload"}</span></td>
                `;
                
                tr.addEventListener("click", () => {
                    drawerPacketBody.querySelectorAll("tr").forEach(r => r.classList.remove("selected"));
                    tr.classList.add("selected");
                    
                    hexViewer.innerHTML = formatHexDump(pkt.hex_data);
                    switchTab("flowHex");
                });

                drawerPacketBody.appendChild(tr);
            });
        } catch (e) {
            drawerPacketBody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:#ff5858;">Failed to load packets: ${e.message}</td></tr>`;
        }
    }

    function switchTab(tabId) {
        tabBtnPackets.classList.toggle("active", tabId === "flowPackets");
        tabBtnHex.classList.toggle("active", tabId === "flowHex");
        
        tabFlowPackets.classList.toggle("active", tabId === "flowPackets");
        tabFlowHex.classList.toggle("active", tabId === "flowHex");
    }

    // Classic Monospace Offset Hex Dump formatter
    function formatHexDump(hexStr) {
        if (!hexStr) return '<div class="hex-empty-state">No payload slice data captured.</div>';
        let result = "";
        for (let i = 0; i < hexStr.length; i += 32) {
            const chunk = hexStr.substring(i, i + 32);
            const offset = (i / 2).toString(16).padStart(4, "0").toUpperCase();
            
            let hexBytes = "";
            let asciiChars = "";
            for (let j = 0; j < chunk.length; j += 2) {
                const byte = chunk.substring(j, j + 2);
                hexBytes += byte + " ";
                if (j === 14) hexBytes += " "; // spaces center column separator
                
                const charCode = parseInt(byte, 16);
                if (charCode >= 32 && charCode <= 126) {
                    asciiChars += String.fromCharCode(charCode);
                } else {
                    asciiChars += ".";
                }
            }
            const paddedHex = hexBytes.padEnd(49, " ");
            result += `<div class="hex-row"><span class="hex-offset">${offset}</span><span class="hex-bytes">${paddedHex}</span><span class="hex-ascii">${asciiChars}</span></div>`;
        }
        return result;
    }

    async function runGeminiAnalysis(flows) {
        try {
            insightContent.innerHTML = "";
            const res = await fetch("/api/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ flows: flows })
            });

            if (!res.ok) throw new Error(await res.text());
            
            const reader = res.body.getReader();
            const decoder = new TextDecoder("utf-8");
            let buffer = "";
            let fullText = "";

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
                            fullText += data.text;
                            insightContent.innerHTML = formatMarkdown(fullText);
                        } catch (err) {}
                    }
                }
            }
            
            if (fullText) {
                fetch("/api/save-explanation", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ explanation: fullText })
                }).catch(err => console.error("Error saving explanation:", err));
            }
        } catch (e) {
            insightContent.innerHTML = `<p class="error-msg">⚠️ AI Analysis failed: ${e.message}. Please check your connection or key status.</p>`;
        }
    }

    async function sendChatMessage() {
        const query = chatInput.value.trim();
        if (!query || activeFlows.length === 0) return;
        
        chatInput.value = "";
        
        renderChatMessage("user", query);
        chatBody.scrollTop = chatBody.scrollHeight;
        
        const botMsgDiv = renderChatMessage("bot", '<div class="typing-indicator"><span></span><span></span><span></span></div>');
        const bubble = botMsgDiv.querySelector(".message-bubble");
        
        try {
            const res = await fetch("/api/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    flows: activeFlows,
                    user_query: query,
                    chat_history: chatHistory
                })
            });
            
            if (!res.ok) throw new Error(await res.text());
            
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
        toast.className = `toast ${type}`;
        
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
        if (topologyAnimationId) {
            cancelAnimationFrame(topologyAnimationId);
            topologyAnimationId = null;
        }
        inspectorDrawer.classList.remove("open");
        dashboardView.style.display = "none";
        chatWidget.style.display = "none";
        chatTrigger.style.display = "none";
        newAnalysisBtn.style.display = "none";
        if (exportReportBtn) exportReportBtn.style.display = "none";
        uploadArea.style.display = "flex";
        activeFileIndicator.innerHTML = '<span class="pulse"></span> Ready';
        activeFlows = [];
        activeGeoIpData = [];
        chatHistory = [];
        if (tabGeo) delete tabGeo.dataset.loaded;
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

    function exportGeoIpToCsv() {
        if (activeGeoIpData.length === 0) {
            showToast("No GeoIP data to export", "error");
            return;
        }
        let csv = "Country,City,IP Address,ISP,Flows Count,Total Volume (Bytes)\n";
        activeGeoIpData.forEach(t => {
            csv += `"${t.country}","${t.city}",${t.ip},"${t.isp}",${t.stats.flows},${t.stats.bytes}\n`;
        });
        const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.setAttribute("href", url);
        link.setAttribute("download", `netscope_geoip_${Date.now()}.csv`);
        link.style.visibility = "hidden";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        showToast("GeoIP data exported as CSV successfully!", "success");
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
        html = html.replace(/<\/ul>\s*<ul>/g, '');

        // Line breaks
        html = html.replace(/\n/g, '<br/>');
        
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
    const dpiPresetSelect = document.getElementById("dpiPresetSelect");
    const dpiSavePresetBtn = document.getElementById("dpiSavePresetBtn");

    const SYSTEM_PRESETS = {
        preset_block_ads: [
            { type: "--block-domain", value: "doubleclick.net" },
            { type: "--block-domain", value: "google-analytics.com" },
            { type: "--block-domain", value: "adsystem.com" }
        ],
        preset_block_social: [
            { type: "--block-domain", value: "facebook.com" },
            { type: "--block-domain", value: "twitter.com" },
            { type: "--block-domain", value: "instagram.com" },
            { type: "--block-domain", value: "tiktok.com" }
        ]
    };

    function loadCustomPresets() {
        if (!dpiPresetSelect) return;
        dpiPresetSelect.innerHTML = `
            <option value="">-- Load Saved Preset --</option>
            <option value="preset_block_ads">Block Ads & Trackers (Preset)</option>
            <option value="preset_block_social">Block Social Media (Preset)</option>
        `;
        const custom = JSON.parse(localStorage.getItem("dpi_custom_presets") || "{}");
        Object.keys(custom).forEach(name => {
            const opt = document.createElement("option");
            opt.value = "custom_" + name;
            opt.textContent = name + " (Custom)";
            dpiPresetSelect.appendChild(opt);
        });
    }

    if (dpiPresetSelect) {
        loadCustomPresets();
        dpiPresetSelect.addEventListener("change", (e) => {
            const val = e.target.value;
            if (!val) return;
            if (SYSTEM_PRESETS[val]) {
                dpiRules = [...SYSTEM_PRESETS[val]];
            } else if (val.startsWith("custom_")) {
                const name = val.substring(7);
                const custom = JSON.parse(localStorage.getItem("dpi_custom_presets") || "{}");
                if (custom[name]) {
                    dpiRules = [...custom[name]];
                }
            }
            renderDpiRules();
            showToast("Preset loaded successfully!", "success");
            dpiPresetSelect.value = "";
        });
    }

    if (dpiSavePresetBtn) {
        dpiSavePresetBtn.addEventListener("click", () => {
            if (dpiRules.length === 0) {
                showToast("Add rules before saving a preset.", "error");
                return;
            }
            const name = prompt("Enter a name for your custom rule preset:");
            if (!name) return;
            const cleanedName = name.trim();
            if (!cleanedName) return;
            const custom = JSON.parse(localStorage.getItem("dpi_custom_presets") || "{}");
            custom[cleanedName] = dpiRules;
            localStorage.setItem("dpi_custom_presets", JSON.stringify(custom));
            loadCustomPresets();
            showToast(`Preset "${cleanedName}" saved locally!`, "success");
        });
    }

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
                renderDashboard(data, true); // Update dynamic stats with skip AI flag
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

    // ============================================
    // TABS & GEOIP INTEGRATION
    // ============================================
    const btnTabFlows = document.getElementById("btnTabFlows");
    const btnTabGeo = document.getElementById("btnTabGeo");
    const tabFlows = document.getElementById("tabFlows");
    const tabGeo = document.getElementById("tabGeo");
    const geoIpTableBody = document.getElementById("geoIpTableBody");

    if (btnTabFlows && btnTabGeo) {
        btnTabFlows.addEventListener("click", () => {
            btnTabFlows.classList.add("active");
            btnTabFlows.style.background = "rgba(30,215,96,0.1)";
            btnTabGeo.classList.remove("active");
            btnTabGeo.style.background = "transparent";
            tabFlows.style.display = "block";
            tabGeo.style.display = "none";
        });
        btnTabGeo.addEventListener("click", () => {
            btnTabGeo.classList.add("active");
            btnTabGeo.style.background = "rgba(30,215,96,0.1)";
            btnTabFlows.classList.remove("active");
            btnTabFlows.style.background = "transparent";
            tabGeo.style.display = "block";
            tabFlows.style.display = "none";
            
            // Fetch GeoIP data if not fetched yet
            if (activeFlows.length > 0 && !tabGeo.dataset.loaded) {
                loadGeoIpData();
            }
        });
    }

    async function loadGeoIpData() {
        if (!activeFlows || activeFlows.length === 0) return;
        
        geoIpTableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-muted);"><i class="fa-solid fa-spinner fa-spin"></i> Gathering geographical data...</td></tr>';
        
        // Extract external IPs
        const ips = new Set();
        const ipStats = {};
        
        activeFlows.forEach(f => {
            // Very basic private IP filter, backend does it better but we aggregate here
            const isPrivate = (ip) => ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.16.") || ip.startsWith("127.");
            
            [f.src_ip, f.dst_ip].forEach(ip => {
                if (!isPrivate(ip)) {
                    ips.add(ip);
                    if (!ipStats[ip]) ipStats[ip] = { flows: 0, bytes: 0 };
                    ipStats[ip].flows++;
                    ipStats[ip].bytes += f.byte_count;
                }
            });
        });

        const ipList = Array.from(ips);
        if (ipList.length === 0) {
            geoIpTableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-muted);">No external IP addresses found in capture.</td></tr>';
            return;
        }

        try {
            const res = await fetch("/api/geoip", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ips: ipList })
            });
            
            if (!res.ok) throw new Error("GeoIP fetch failed");
            
            const data = await res.json();
            const results = data.results || {};
            
            // Map results to array and sort by bytes (Top Talkers)
            const topTalkers = Object.entries(results).map(([ip, info]) => {
                return {
                    ip,
                    country: info.country || "Unknown",
                    countryCode: info.countryCode ? info.countryCode.toLowerCase() : "",
                    city: info.city || "Unknown",
                    isp: info.isp || "Unknown",
                    stats: ipStats[ip]
                };
            }).sort((a, b) => b.stats.bytes - a.stats.bytes);
            
            activeGeoIpData = topTalkers;
            geoIpTableBody.innerHTML = "";
            topTalkers.forEach(t => {
                const tr = document.createElement("tr");
                const flagHtml = t.countryCode ? `<img src="https://flagcdn.com/16x12/${t.countryCode}.png" alt="${t.countryCode}" style="margin-right: 8px; vertical-align: middle;">` : '🏳️ ';
                tr.innerHTML = `
                    <td>${flagHtml}${t.country}</td>
                    <td>${t.city}</td>
                    <td><code>${t.ip}</code></td>
                    <td style="max-width: 150px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${t.isp}">${t.isp}</td>
                    <td>${t.stats.flows}</td>
                    <td>${(t.stats.bytes / 1024).toFixed(1)} KB</td>
                `;
                geoIpTableBody.appendChild(tr);
            });
            
            tabGeo.dataset.loaded = "true";
            
        } catch (e) {
            geoIpTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 2rem; color: #ff6b6b;">Failed to load GeoIP data: ${e.message}</td></tr>`;
        }
    }
    
    // Theme Toggle Logic
    const themeToggleBtn = document.getElementById("themeToggleBtn");
    if (themeToggleBtn) {
        // Load saved theme
        const savedTheme = localStorage.getItem("theme") || "dark";
        if (savedTheme === "light") {
            document.body.classList.add("light-theme");
            themeToggleBtn.innerHTML = '<i class="fa-solid fa-sun"></i>';
        } else {
            document.body.classList.remove("light-theme");
            themeToggleBtn.innerHTML = '<i class="fa-solid fa-moon"></i>';
        }

        themeToggleBtn.addEventListener("click", () => {
            const isLight = document.body.classList.toggle("light-theme");
            if (isLight) {
                localStorage.setItem("theme", "light");
                themeToggleBtn.innerHTML = '<i class="fa-solid fa-sun"></i>';
            } else {
                localStorage.setItem("theme", "dark");
                themeToggleBtn.innerHTML = '<i class="fa-solid fa-moon"></i>';
            }
            // Update line chart colors
            updateChartsTheme();
        });
    }

    let bandwidthChartInstance = null;

    function renderBandwidthTimeline(packets) {
        if (!packets || packets.length === 0) return;

        // Group packets by second
        const timeMap = {};
        let minTime = Infinity;
        let maxTime = -Infinity;

        packets.forEach(p => {
            const sec = Math.floor(p.timestamp);
            if (sec < minTime) minTime = sec;
            if (sec > maxTime) maxTime = sec;
            timeMap[sec] = (timeMap[sec] || 0) + p.length;
        });

        const labels = [];
        const data = [];
        
        if (maxTime === minTime) {
            maxTime += 1;
        }

        for (let t = minTime; t <= maxTime; t++) {
            const date = new Date(t * 1000);
            const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            labels.push(timeStr);
            // Convert to KB
            data.push(Math.round((timeMap[t] || 0) / 102.4) / 10.0); // KB/s
        }

        const ctx = document.getElementById("bandwidthChart").getContext("2d");
        
        if (bandwidthChartInstance) {
            bandwidthChartInstance.destroy();
        }

        const isLight = document.body.classList.contains("light-theme");
        const gridColor = isLight ? "#e2e8f0" : "#1e293b";
        const textColor = isLight ? "#64748b" : "#94a3b8";
        const borderColor = isLight ? "#0284c7" : "#22d3ee";
        const gradientBg = ctx.createLinearGradient(0, 0, 0, 200);
        gradientBg.addColorStop(0, isLight ? "rgba(2, 132, 199, 0.15)" : "rgba(34, 211, 238, 0.15)");
        gradientBg.addColorStop(1, "rgba(34, 211, 238, 0)");

        bandwidthChartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Bandwidth (KB/s)',
                    data: data,
                    borderColor: borderColor,
                    backgroundColor: gradientBg,
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2,
                    pointRadius: labels.length > 50 ? 0 : 3,
                    pointHoverRadius: 5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    x: {
                        grid: {
                            color: gridColor,
                            drawBorder: false
                        },
                        ticks: {
                            color: textColor,
                            maxTicksLimit: 8
                        }
                    },
                    y: {
                        grid: {
                            color: gridColor,
                            drawBorder: false
                        },
                        ticks: {
                            color: textColor,
                            callback: function(value) {
                                return value + ' KB/s';
                            }
                        },
                        suggestedMin: 0
                    }
                }
            }
        });
    }

    function updateChartsTheme() {
        if (!bandwidthChartInstance) return;
        const isLight = document.body.classList.contains("light-theme");
        const gridColor = isLight ? "#e2e8f0" : "#1e293b";
        const textColor = isLight ? "#64748b" : "#94a3b8";
        const borderColor = isLight ? "#0284c7" : "#22d3ee";
        
        const ctx = document.getElementById("bandwidthChart").getContext("2d");
        const gradientBg = ctx.createLinearGradient(0, 0, 0, 200);
        gradientBg.addColorStop(0, isLight ? "rgba(2, 132, 199, 0.15)" : "rgba(34, 211, 238, 0.15)");
        gradientBg.addColorStop(1, "rgba(34, 211, 238, 0)");

        bandwidthChartInstance.data.datasets[0].borderColor = borderColor;
        bandwidthChartInstance.data.datasets[0].backgroundColor = gradientBg;
        bandwidthChartInstance.options.scales.x.grid.color = gridColor;
        bandwidthChartInstance.options.scales.x.ticks.color = textColor;
        bandwidthChartInstance.options.scales.y.grid.color = gridColor;
        bandwidthChartInstance.options.scales.y.ticks.color = textColor;
        bandwidthChartInstance.update();
    }

    function renderPacketTable(packets) {
        const modal = document.getElementById("packetModalOverlay");
        const tbody = document.getElementById("packetTableBody");
        const closeBtn = document.getElementById("closePacketModal");
        const viewBtn = document.getElementById("viewPacketTableBtn");

        if (!modal || !tbody) return;

        tbody.innerHTML = "";
        if (!packets || packets.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No packet data available.</td></tr>';
            return;
        }

        packets.forEach(p => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${p.timestamp.toFixed(6)}</td>
                <td><code>${p.src_ip}${p.src_port ? ':' + p.src_port : ''}</code></td>
                <td><code>${p.dst_ip}${p.dst_port ? ':' + p.dst_port : ''}</code></td>
                <td><span class="proto-badge badge-${p.protocol.toLowerCase()}">${p.protocol}</span></td>
                <td>${p.length} B</td>
                <td class="info-cell" title="${p.tcp_flags || ''}">${p.tcp_flags ? '[' + p.tcp_flags + ']' : ''} ${p.sni || p.http_host || p.dns_query || ''}</td>
            `;
            tbody.appendChild(tr);
        });

        if (viewBtn) {
            const newBtn = viewBtn.cloneNode(true);
            viewBtn.parentNode.replaceChild(newBtn, viewBtn);
            newBtn.addEventListener("click", () => {
                modal.style.display = "flex";
            });
        }

        if (closeBtn) {
            closeBtn.addEventListener("click", () => {
                modal.style.display = "none";
            });
        }

        modal.addEventListener("click", (e) => {
            if (e.target === modal) {
                modal.style.display = "none";
            }
        });
    }

    // Reset GeoIP loaded state when new file uploaded
    const originalRenderTable = window.renderFlowTable;
    // Note: renderFlowTable is actually not globally exposed. We must hook into the analysis render logic.
    // The easiest way is to observe activeFlows or hook when activeFlows is populated (which is done in startAnalysis/fetchDemo).
    // Let's just clear the dataset loaded flag in UI reset.
    const uploadInput = document.getElementById("pcapFile");
    if (uploadInput) {
        uploadInput.addEventListener("change", () => {
            tabGeo.dataset.loaded = "";
        });
    }

});
