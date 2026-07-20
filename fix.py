import re

with open('frontend/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Extract renderPacketTable from where it was wrongly placed
wrong_insertion = '''            function renderPacketTable(packets) {
        if (!packets || packets.length === 0) return;
        
        let modal = document.getElementById("packetModal");
        if (!modal) {
            modal = document.createElement("div");
            modal.id = "packetModal";
            modal.className = "modal-overlay";
            modal.style.display = "none";
            
            const content = document.createElement("div");
            content.className = "modal-content";
            
            const header = document.createElement("div");
            header.className = "modal-header";
            header.innerHTML = `
                <h3><i class="fa-solid fa-list-ul"></i> Packet Details</h3>
                <button class="btn-close" id="closePacketModal"><i class="fa-solid fa-xmark"></i></button>
            `;
            
            const body = document.createElement("div");
            body.className = "modal-body";
            
            const table = document.createElement("table");
            table.className = "packet-table";
            table.innerHTML = `
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Source</th>
                        <th>Dest</th>
                        <th>Protocol</th>
                        <th>Length</th>
                        <th>Info</th>
                    </tr>
                </thead>
                <tbody id="packetTableBody"></tbody>
            `;
            
            body.appendChild(table);
            content.appendChild(header);
            content.appendChild(body);
            modal.appendChild(content);
            document.body.appendChild(modal);
            
            document.getElementById("closePacketModal").addEventListener("click", () => {
                modal.style.display = "none";
            });
            
            modal.addEventListener("click", (e) => {
                if(e.target === modal) modal.style.display = "none";
            });
        }
        
        const tbody = document.getElementById("packetTableBody");
        tbody.innerHTML = "";
        
        const displayPackets = packets.slice(0, 100);
        
        displayPackets.forEach(p => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${p.timestamp_sec.toFixed(4)}</td>
                <td><code>${p.src_ip}:${p.src_port || ''}</code></td>
                <td><code>${p.dst_ip}:${p.dst_port || ''}</code></td>
                <td><span class="proto-badge">${p.protocol}</span></td>
                <td>${p.length}</td>
                <td style="font-size: 0.8rem; color: var(--text-muted);">${p.is_syn ? '[SYN] ' : ''}${p.is_fin ? '[FIN] ' : ''} Seq=${p.seq || 0}</td>
            `;
            tbody.appendChild(tr);
        });
        
        const viewBtn = document.getElementById("viewPacketTableBtn");
        if (viewBtn) {
            const newBtn = viewBtn.cloneNode(true);
            viewBtn.parentNode.replaceChild(newBtn, viewBtn);
            newBtn.addEventListener("click", () => {
                modal.style.display = "flex";
            });
        }
    }

    let bandwidthChartInstance = null;'''

content = content.replace(wrong_insertion, 'let asciiChars = "";')

# 2. Insert renderPacketTable correctly before renderBandwidthTimeline
correct_code = '''
    function renderPacketTable(packets) {
        if (!packets || packets.length === 0) return;
        
        let modal = document.getElementById("packetModal");
        if (!modal) {
            modal = document.createElement("div");
            modal.id = "packetModal";
            modal.className = "modal-overlay";
            modal.style.display = "none";
            
            const content = document.createElement("div");
            content.className = "modal-content";
            
            const header = document.createElement("div");
            header.className = "modal-header";
            header.innerHTML = `
                <h3><i class="fa-solid fa-list-ul"></i> Packet Details</h3>
                <button class="btn-close" id="closePacketModal"><i class="fa-solid fa-xmark"></i></button>
            `;
            
            const body = document.createElement("div");
            body.className = "modal-body";
            
            const table = document.createElement("table");
            table.className = "packet-table";
            table.innerHTML = `
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Source</th>
                        <th>Dest</th>
                        <th>Protocol</th>
                        <th>Length</th>
                        <th>Info</th>
                    </tr>
                </thead>
                <tbody id="packetTableBody"></tbody>
            `;
            
            body.appendChild(table);
            content.appendChild(header);
            content.appendChild(body);
            modal.appendChild(content);
            document.body.appendChild(modal);
            
            document.getElementById("closePacketModal").addEventListener("click", () => {
                modal.style.display = "none";
            });
            
            modal.addEventListener("click", (e) => {
                if(e.target === modal) modal.style.display = "none";
            });
        }
        
        const tbody = document.getElementById("packetTableBody");
        tbody.innerHTML = "";
        
        const displayPackets = packets.slice(0, 100);
        
        displayPackets.forEach(p => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${p.timestamp_sec.toFixed(4)}</td>
                <td><code>${p.src_ip}:${p.src_port || ''}</code></td>
                <td><code>${p.dst_ip}:${p.dst_port || ''}</code></td>
                <td><span class="proto-badge">${p.protocol}</span></td>
                <td>${p.length}</td>
                <td style="font-size: 0.8rem; color: var(--text-muted);">${p.is_syn ? '[SYN] ' : ''}${p.is_fin ? '[FIN] ' : ''} Seq=${p.seq || 0}</td>
            `;
            tbody.appendChild(tr);
        });
        
        const viewBtn = document.getElementById("viewPacketTableBtn");
        if (viewBtn) {
            const newBtn = viewBtn.cloneNode(true);
            viewBtn.parentNode.replaceChild(newBtn, viewBtn);
            newBtn.addEventListener("click", () => {
                modal.style.display = "flex";
            });
        }
    }

    let bandwidthChartInstance = null;
    function renderBandwidthTimeline'''

content = content.replace('    let bandwidthChartInstance = null;\n    function renderBandwidthTimeline', correct_code)

# 3. Add Theme Toggle Logic
theme_toggle_logic = '''
    // Theme Toggle Logic
    const themeToggleBtn = document.querySelector(".theme-toggle-btn");
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener("click", () => {
            const body = document.body;
            if (body.classList.contains("light-mode")) {
                body.classList.remove("light-mode");
                themeToggleBtn.innerHTML = '<i class="fa-solid fa-moon"></i>';
                Chart.defaults.color = "#8b949e";
            } else {
                body.classList.add("light-mode");
                themeToggleBtn.innerHTML = '<i class="fa-solid fa-sun"></i>';
                Chart.defaults.color = "#4b5563";
            }
            if (bandwidthChartInstance) {
                bandwidthChartInstance.update();
            }
        });
    }
'''
content = content.replace('document.addEventListener("DOMContentLoaded", () => {', 'document.addEventListener("DOMContentLoaded", () => {' + theme_toggle_logic)

with open('frontend/app.js', 'w', encoding='utf-8') as f:
    f.write(content)
