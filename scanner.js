document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const dependencyInput = document.getElementById('dependencyInput');
    const ecosystemSelect = document.getElementById('ecosystemSelect');
    const resultsContainer = document.getElementById('resultsContainer');
    const statusMessage = document.getElementById('statusMessage');

    scanBtn.addEventListener('click', performScan);

    async function performScan() {
        const rawInput = dependencyInput.value.trim();
        const ecosystem = ecosystemSelect.value;
        
        if (!rawInput) return;

        resultsContainer.innerHTML = '';
        statusMessage.classList.remove('hidden');
        statusMessage.classList.add('pulse-text');
        statusMessage.style.color = '';
        statusMessage.textContent = 'Parsing manifest and generating query payload...';

        
        const packages = parseManifest(rawInput);
        if (packages.length === 0) {
            showError("Could not detect any valid packages. Please check your syntax.");
            return;
        }

        statusMessage.textContent = `Querying OSV.dev for ${packages.length} dependencies...`;

        
        const queries = packages.map(pkg => ({
            package: { name: pkg.name, ecosystem: ecosystem },
            version: pkg.version
        }));

        try {
            
            const response = await fetch('https://api.osv.dev/v1/querybatch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ queries })
            });

            if (!response.ok) throw new Error(`OSV API returned ${response.status}`);

            const data = await response.json();
            statusMessage.classList.add('hidden');
            
            
            renderResults(packages, data.results);

        } catch (error) {
            showError(`Scan failed: ${error.message}`);
        }
    }

    
    function parseManifest(raw) {
        let deps = [];
        

        try {
            const json = JSON.parse(raw);
            const allDeps = { ...(json.dependencies || {}), ...(json.devDependencies || {}) };
            
            for (const [name, version] of Object.entries(allDeps)) {
                const cleanVersion = version.replace(/[\^~><=xX*]/g, '').trim();
                if (cleanVersion) deps.push({ name, version: cleanVersion });
            }
            if (deps.length > 0) return deps;
        } catch (e) {

        }


        const lines = raw.split('\n');
        lines.forEach(line => {
            line = line.trim();
            if (!line || line.startsWith('#') || line.startsWith('//')) return;


            let match = line.match(/^([a-zA-Z0-9_\-\.]+)[=!><~]+([0-9\.]+.*)/);
            if (match) {
                deps.push({ name: match[1], version: match[2].replace(/[\^~><=]/g, '').trim() });
                return;
            }


            match = line.match(/^([a-zA-Z0-9_\-\.]+):([0-9\.]+.*)/);
            if (match) {
                deps.push({ name: match[1], version: match[2].trim() });
            }
        });

        return deps;
    }


    function renderResults(packages, results) {
        let matchCount = 0;

        const sanitize = (html) => typeof DOMPurify !== 'undefined' ? DOMPurify.sanitize(html) : html;


        const stats = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            unrated: 0,
            totalVulns: 0
        };

        const cardsHtml = [];
        

        let reportDetailsText = `--- DETAILED FINDINGS ---\n\n`;

        results.forEach((result, index) => {
            const pkg = packages[index];
            
            if (!result.vulns || result.vulns.length === 0) return;

            result.vulns.forEach((vuln, vIndex) => {
                matchCount++;
                stats.totalVulns++;
                

                const cves = (vuln.aliases || []).filter(alias => alias.startsWith('CVE-'));
                const primaryId = cves.length > 0 ? cves[0] : vuln.id;
                const altIds = vuln.id !== primaryId ? `<span class="tag" style="background:#eee; color:#333;">OSV: ${sanitize(vuln.id)}</span>` : '';
                

                let severityClass = 'tag-medium';
                let severityText = 'UNRATED';
                let cvssInfo = '';


                if (vuln.database_specific && vuln.database_specific.severity) {
                     severityText = vuln.database_specific.severity.toUpperCase();
                } else if (vuln.ecosystem_specific && vuln.ecosystem_specific.severity) {
                     severityText = vuln.ecosystem_specific.severity.toUpperCase();
                }


                if (vuln.severity && vuln.severity.length > 0) {
                    const cvss = vuln.severity[0]; 
                    cvssInfo = `<div style="margin-top: 15px; font-family: var(--font-mono); font-size: 0.85rem; padding: 10px; background: #f9f9f9; border-radius: 4px;">
                                    <strong>CVSS Vector (${sanitize(cvss.type)}):</strong> ${sanitize(cvss.score)}
                                </div>`;
                    
                    if (severityText === 'UNRATED') severityText = 'CVSS-SCORED';
                } 


                const upperText = severityText.toUpperCase();

                if (upperText.includes('CRITICAL')) { 
                    severityClass = 'tag-critical'; stats.critical++; severityText = 'CRITICAL';
                } else if (upperText.includes('HIGH')) { 
                    severityClass = 'tag-high'; stats.high++; severityText = 'HIGH';
                } else if (upperText.includes('LOW')) { 
                    severityClass = 'tag-low'; stats.low++; severityText = 'LOW';
                } else if (upperText.includes('UNRATED') || upperText === 'UNKNOWN') {
                    severityClass = 'tag-medium'; severityText = 'UNRATED'; stats.unrated++;
                } else { 
                    severityClass = 'tag-medium'; stats.medium++; 
                    if (upperText === 'CVSS-SCORED') severityText = 'MEDIUM (CVSS)';
                }


                const shortDesc = vuln.summary || 'No brief summary available.';
                let fullDetails = vuln.details || 'No expanded details provided by OSV database.';
                fullDetails = fullDetails.replace(/\n\n/g, '</p><p>').replace(/\n/g, '<br>');
                
                const cleanSummary = sanitize(shortDesc);
                const cleanDetails = sanitize(`<p>${fullDetails}</p>`);

               
                let refsHtml = '';
                if (vuln.references && vuln.references.length > 0) {
                    const safeRefs = vuln.references.map(r => {
                        const safeUrl = sanitize(r.url);
                        return `<li><a href="${safeUrl}" target="_blank" style="color: var(--app-spicy); word-break: break-all;">${safeUrl}</a> <span style="color: #666; font-size: 0.8rem;">(${sanitize(r.type)})</span></li>`;
                    }).join('');
                    refsHtml = `<div style="margin-top: 15px;"><strong>References:</strong><ul style="padding-left: 20px; font-size: 0.9rem;">${safeRefs}</ul></div>`;
                }


                let affectedHtml = '';
                if (vuln.affected && vuln.affected.length > 0) {
                    const safeAffected = vuln.affected.map(a => {
                        let pkgName = a.package ? a.package.name : 'Unknown Package';
                        let versionList = a.versions ? a.versions.slice(0, 10).join(', ') + (a.versions.length > 10 ? '...' : '') : 'See OSV for ranges';
                        return `<li><strong>${sanitize(pkgName)}:</strong> ${sanitize(versionList)}</li>`;
                    }).join('');
                    affectedHtml = `<div style="margin-top: 15px;"><strong>Affected Versions/Ranges:</strong><ul style="padding-left: 20px; font-size: 0.9rem;">${safeAffected}</ul></div>`;
                }


                let fixesHtml = '';
                let foundFixes = [];
                
                if (vuln.affected && vuln.affected.length > 0) {
                    vuln.affected.forEach(a => {
                        if (a.ranges) {
                            a.ranges.forEach(r => {
                                if (r.events) {
                                    r.events.forEach(e => {
                                        if (e.fixed) {
                                            const pkgName = a.package ? a.package.name : pkg.name;
                                            foundFixes.push(`Update ${sanitize(pkgName)} to ${sanitize(e.fixed)}`);
                                        }
                                    });
                                }
                            });
                        }
                    });
                }

                const uniqueFixes = [...new Set(foundFixes)];

                if (uniqueFixes.length > 0) {
                    fixesHtml = `
                        <div style="margin-top: 15px; padding: 12px; background: #ecfdf5; border-left: 4px solid #10B981; border-radius: 4px;">
                            <strong style="color: #047857;">Suggested Remediation:</strong>
                            <ul style="padding-left: 20px; font-size: 0.9rem; margin-top: 5px; margin-bottom: 0; color: #065f46;">
                                ${uniqueFixes.map(f => `<li>${f}</li>`).join('')}
                            </ul>
                        </div>`;
                } else {
                    fixesHtml = `
                        <div style="margin-top: 15px; padding: 12px; background: #fffbeb; border-left: 4px solid #f59e0b; border-radius: 4px;">
                            <strong style="color: #b45309;">Remediation Info:</strong>
                            <p style="font-size: 0.9rem; margin-top: 5px; margin-bottom: 0; color: #92400e;">
                                No direct patch version provided. Check references for manual mitigations.
                            </p>
                        </div>`;
                }


                reportDetailsText += `[${severityText}] ${primaryId} in ${pkg.name} (@${pkg.version})\n`;
                reportDetailsText += `Summary: ${shortDesc.replace(/\n/g, ' ')}\n`;
                reportDetailsText += `Fix: ${uniqueFixes.length > 0 ? uniqueFixes.join(', ') : 'No direct patch provided. Review references.'}\n`;
                reportDetailsText += `Details Link: https://osv.dev/vulnerability/${vuln.id}\n`;
                reportDetailsText += `--------------------------------------------------\n\n`;

                
                const card = document.createElement('div');
                card.className = 'card fade-in-up';
                card.style.animationDelay = `${(matchCount % 10) * 0.05}s`;

                card.innerHTML = `
                    <div class="card-header">
                        <div>
                            <h3 class="card-title">${sanitize(primaryId)}</h3>
                            <div style="font-family: var(--font-mono); font-size: 0.9rem; color: var(--app-spicy); margin-top: 4px;">
                                ${sanitize(pkg.name)} @ ${sanitize(pkg.version)}
                            </div>
                        </div>
                        <div class="tags-group">
                            <span class="tag ${severityClass}">${sanitize(severityText)}</span>
                            ${altIds}
                        </div>
                    </div>
                    
                    <p class="text-body">${cleanSummary}</p>
                    
                    <div class="expanded-content hidden" style="display: none; margin-top: 15px; padding-top: 15px; border-top: 1px solid var(--app-border);">
                        ${fixesHtml}
                        <div class="text-body" style="font-size: 0.95rem; line-height: 1.6; margin-top:15px;">${cleanDetails}</div>
                        ${cvssInfo}
                        ${affectedHtml}
                        ${refsHtml}
                    </div>

                    <div class="card-footer" style="margin-top: 15px; display: flex; gap: 10px; align-items: center;">
                        <button class="btn btn-primary toggle-btn" style="min-width: 120px;">Read More</button>
                        <a href="https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}" target="_blank" style="text-decoration: none; font-size: 0.9rem; color: #666;">
                            View external record &rarr;
                        </a>
                    </div>
                `;


                const toggleBtn = card.querySelector('.toggle-btn');
                const expandedContent = card.querySelector('.expanded-content');

                toggleBtn.addEventListener('click', () => {
                    const isHidden = expandedContent.style.display === 'none';
                    expandedContent.style.display = isHidden ? 'block' : 'none';
                    toggleBtn.textContent = isHidden ? 'Show Less' : 'Read More';
                    
                    toggleBtn.classList.toggle('btn-secondary', isHidden);
                    toggleBtn.classList.toggle('btn-primary', !isHidden);
                });

                cardsHtml.push(card);
            });
        });


        if (matchCount > 0) {

            let fullReportText = `==================================================\n`;
            fullReportText += ` TISH - DEPENDENCY SCAN REPORT\n`;
            fullReportText += `==================================================\n`;
            fullReportText += `Date: ${new Date().toLocaleString()}\n`;
            fullReportText += `Packages Scanned: ${packages.length}\n`;
            fullReportText += `Vulnerabilities Found: ${stats.totalVulns}\n\n`;
            fullReportText += `--- SEVERITY SUMMARY ---\n`;
            fullReportText += `CRITICAL: ${stats.critical} | HIGH: ${stats.high} | MEDIUM: ${stats.medium} | LOW: ${stats.low} | UNRATED: ${stats.unrated}\n\n`;
            fullReportText += reportDetailsText;

            const summaryDiv = document.createElement('div');
            summaryDiv.className = 'fade-in-up';
            summaryDiv.style.gridColumn = "1 / -1"; 
            summaryDiv.style.background = "var(--app-white)";
            summaryDiv.style.border = "1px solid var(--app-border)";
            summaryDiv.style.borderRadius = "var(--radius-subtle)";
            summaryDiv.style.padding = "20px";
            summaryDiv.style.marginBottom = "20px";
            summaryDiv.style.display = "flex";
            summaryDiv.style.flexWrap = "wrap";
            summaryDiv.style.gap = "20px";
            summaryDiv.style.justifyContent = "space-around";
            summaryDiv.style.alignItems = "center";
            summaryDiv.style.boxShadow = "0 2px 8px rgba(0,0,0,0.02)";

            summaryDiv.innerHTML = `
                <div style="text-align: center;">
                    <div style="font-size: 2rem; font-weight: 700; color: var(--app-black);">${packages.length}</div>
                    <div style="font-size: 0.85rem; color: #666; text-transform: uppercase;">Packages Scanned</div>
                </div>
                <div style="text-align: center;">
                    <div style="font-size: 2rem; font-weight: 700; color: var(--app-spicy);">${stats.totalVulns}</div>
                    <div style="font-size: 0.85rem; color: #666; text-transform: uppercase;">Vulns Found</div>
                </div>
                <div style="display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding-left: 20px; border-left: 1px solid var(--app-border);">
                    ${stats.critical > 0 ? `<span class="tag tag-critical" style="font-size: 1rem; padding: 6px 12px;">${stats.critical} CRITICAL</span>` : ''}
                    ${stats.high > 0     ? `<span class="tag tag-high" style="font-size: 1rem; padding: 6px 12px;">${stats.high} HIGH</span>` : ''}
                    ${stats.medium > 0   ? `<span class="tag tag-medium" style="font-size: 1rem; padding: 6px 12px;">${stats.medium} MEDIUM</span>` : ''}
                    ${stats.low > 0      ? `<span class="tag tag-low" style="font-size: 1rem; padding: 6px 12px;">${stats.low} LOW</span>` : ''}
                    ${stats.unrated > 0  ? `<span class="tag" style="background: #e2e8f0; color: #475569; font-size: 1rem; padding: 6px 12px;">${stats.unrated} UNRATED</span>` : ''}
                </div>
                <div style="width: 100%; text-align: center; margin-top: 10px; border-top: 1px solid var(--app-border); padding-top: 15px;">
                    <button id="downloadReportBtn" class="btn" style="background: var(--app-black); color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-family: var(--font-primary);">
                        ↓ Download Text Report
                    </button>
                </div>
            `;
            
            resultsContainer.appendChild(summaryDiv);
            cardsHtml.forEach(card => resultsContainer.appendChild(card));


            const downloadBtn = document.getElementById('downloadReportBtn');
            downloadBtn.addEventListener('click', () => {
                const blob = new Blob([fullReportText], { type: 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;

                a.download = `tish-report-${Math.floor(Date.now() / 1000)}.txt`; 
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            });

        } else {
            resultsContainer.innerHTML = `
                <div style="text-align: center; padding: 40px; color: #666;">
                    <h3 style="margin-bottom: 8px; color: #10B981;">Clean Scan!</h3>
                    <p>No known vulnerabilities found in the ${packages.length} scanned dependencies.</p>
                </div>`;
        }
    }

    function showError(msg) {
        statusMessage.classList.remove('hidden', 'pulse-text');
        statusMessage.style.color = 'var(--app-spicy)';
        statusMessage.textContent = msg;
    }
});