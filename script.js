document.addEventListener('DOMContentLoaded', () => {
    initHotFeed();
    setInterval(initHotFeed, 600000);
    
    
    const searchInput = document.getElementById('searchInput');
    const searchBtn = document.getElementById('searchBtn');
    const resultsContainer = document.getElementById('resultsContainer');
    const statusMessage = document.getElementById('statusMessage');
    const articleContainer = document.getElementById('articleContainer');
    const backToResultsBtn = document.getElementById('backToResultsBtn');
    
    const tabCve = document.getElementById('tab-cve');
    const tabMalware = document.getElementById('tab-malware');

    let searchMode = 'cve'; 
    const filterSidebar = document.getElementById('filterSidebar');
    const filterCritical = document.getElementById('filter-critical');
    const filterHigh = document.getElementById('filter-high');
    const filterMedium = document.getElementById('filter-medium');
    const filterLow = document.getElementById('filter-low');
    const filterKev = document.getElementById('filter-kev');
    const filterEpss = document.getElementById('filter-epss');
    const epssValueDisplay = document.getElementById('epss-value');
    const resetFiltersBtn = document.getElementById('resetFiltersBtn');

    
    let currentVulnerabilities = [];
    let currentEpssDataMap = {};
    let mitreDataCache = null;
    
    let watchlist = JSON.parse(localStorage.getItem('tish_watchlist')) || [];
    let webhookUrl = localStorage.getItem('tish_webhook') || '';
    let notifiedFeedIds = JSON.parse(localStorage.getItem('tish_notified')) || [];

   
    const applyFilters = () => renderFilteredCves();
    [filterCritical, filterHigh, filterMedium, filterLow, filterKev].forEach(el => el.addEventListener('change', applyFilters));
    
    filterEpss.addEventListener('input', (e) => {
        epssValueDisplay.textContent = `${e.target.value}%`;
        applyFilters();
    });

    resetFiltersBtn.addEventListener('click', () => {
        filterCritical.checked = true; filterHigh.checked = true;
        filterMedium.checked = true; filterLow.checked = true;
        filterKev.checked = false;
        filterEpss.value = 0; epssValueDisplay.textContent = '0%';
        applyFilters();
    });

    
    tabCve.addEventListener('click', () => {
        searchMode = 'cve';
        tabCve.className = 'btn btn-primary';
        tabMalware.className = 'btn btn-secondary';
        searchInput.placeholder = "e.g., Apache Tomcat, OpenSSH, Windows...";
        searchInput.value = ''; 
        resetView();
    });

    tabMalware.addEventListener('click', () => {
        searchMode = 'malware';
        tabMalware.className = 'btn btn-primary';
        tabCve.className = 'btn btn-secondary';
        searchInput.placeholder = "e.g., Stuxnet, WannaCry, Emotet...";
        searchInput.value = ''; 
        resetView();
    });

    function resetView() {
        resultsContainer.innerHTML = '';
        statusMessage.textContent = '';
        statusMessage.classList.add('hidden');
        articleContainer.classList.add('hidden');
        resultsContainer.classList.remove('hidden');
        filterSidebar.classList.add('hidden'); 
        statusMessage.style.color = '';
    }

    
    searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') performSearch();
    });

    searchBtn.addEventListener('click', performSearch);

    function performSearch() {
        const query = searchInput.value.trim();
        if (!query) return;

        resetView();
        statusMessage.classList.remove('hidden');
        statusMessage.classList.add('pulse-text');

        if (searchMode === 'cve') {
            fetchCVE(query);
        } else {
            fetchMalware(query);
        }
    }

    
    async function fetchCVE(query) {
        statusMessage.textContent = 'Fetching telemetry from NVD database...';
        try {
            const apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=50`;
            const response = await fetch(apiUrl);
            
            if (!response.ok) {
                if(response.status === 403) throw new Error("Rate limit exceeded. Please wait 30 seconds and try again.");
                throw new Error(`API returned status: ${response.status}`);
            }

            const data = await response.json();
            
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                statusMessage.textContent = 'Enriching telemetry with EPSS intelligence...';
                
                const cveIds = data.vulnerabilities.map(item => item.cve.id).join(',');
                currentEpssDataMap = {}; 
                
                try {
                    const epssResponse = await fetch(`https://api.first.org/data/v1/epss?cve=${cveIds}`);
                    if (epssResponse.ok) {
                        const epssData = await epssResponse.json();
                        if (epssData.data) {
                            epssData.data.forEach(item => {
                                currentEpssDataMap[item.cve] = {
                                    score: (parseFloat(item.epss) * 100).toFixed(2),
                                    percentile: (parseFloat(item.percentile) * 100).toFixed(0)
                                };
                            });
                        }
                    }
                } catch (epssErr) {
                    console.warn("EPSS Enrichment failed. Proceeding with base NVD data.", epssErr);
                }

                statusMessage.classList.add('hidden');
                statusMessage.classList.remove('pulse-text');
                filterSidebar.classList.remove('hidden'); 
                
                currentVulnerabilities = data.vulnerabilities;
                renderFilteredCves();

            } else {
                statusMessage.classList.remove('pulse-text');
                statusMessage.textContent = `No known vulnerabilities found for "${query}".`;
            }
        } catch (error) {
            handleError(error);
        }
    }

    function renderFilteredCves() {
        resultsContainer.innerHTML = '';
        
        const allowedSeverities = [];
        if(filterCritical.checked) allowedSeverities.push('CRITICAL');
        if(filterHigh.checked) allowedSeverities.push('HIGH');
        if(filterMedium.checked) allowedSeverities.push('MEDIUM');
        
        const requireKev = filterKev.checked;
        const minEpssScore = parseFloat(filterEpss.value);

        let matchCount = 0;

        currentVulnerabilities.forEach((item, index) => {
            const cve = item.cve;
            
            if (requireKev && !cve.cisaExploitAdd) return;

            let currentEpss = 0;
            if (currentEpssDataMap[cve.id]) {
                currentEpss = parseFloat(currentEpssDataMap[cve.id].score);
            }
            if (currentEpss < minEpssScore) return;

            const metrics = cve.metrics || {};
            const cvssDataObj = metrics.cvssMetricV31?.[0] || metrics.cvssMetricV30?.[0] || metrics.cvssMetricV2?.[0];
            let severity = 'UNKNOWN';
            let score = 'N/A';
            
            if (cvssDataObj) {
                severity = (cvssDataObj.cvssData.baseSeverity || cvssDataObj.baseSeverity || 'UNKNOWN').toUpperCase();
                score = cvssDataObj.cvssData.baseScore;
            }

            if (!allowedSeverities.includes(severity)) {
                if (!filterLow.checked && (severity === 'LOW' || severity === 'NONE' || severity === 'UNKNOWN')) return;
            }

            matchCount++;
            
            const descriptions = cve.descriptions || [];
            const descObj = descriptions.find(d => d.lang === 'en');
            const description = descObj ? descObj.value : 'No description available.';
            const pubDate = new Date(cve.published || new Date()).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });

            let kevHtml = cve.cisaExploitAdd ? `<span class="tag tag-critical" style="border: 1px solid #ff4500;" title="Listed in CISA KEV Catalog.">CISA KEV</span>` : '';
            
            let severityHtml = '';
            if (cvssDataObj) {
                let badgeClass = severity === 'CRITICAL' ? 'tag-critical' : severity === 'HIGH' ? 'tag-high' : severity === 'MEDIUM' ? 'tag-medium' : 'tag-low';
                severityHtml = `<span class="tag ${badgeClass}">CVSS: ${score} (${severity})</span>`;
            }

            let epssHtml = '';
            if (currentEpssDataMap[cve.id]) {
                const epss = currentEpssDataMap[cve.id];
                const epssClass = parseFloat(epss.score) > 10.00 ? 'tag-epss-critical' : 'tag-epss';
                epssHtml = `<span class="tag ${epssClass}">EPSS: ${epss.score}%</span>`;
            }

            const card = document.createElement('div');
            card.className = 'card fade-in-up'; 
            card.style.animationDelay = `${(matchCount % 10) * 0.05}s`;
            
            const cleanDesc = typeof DOMPurify !== 'undefined' ? DOMPurify.sanitize(description) : description;

            card.innerHTML = `
                <div class="card-header">
                    <h3 class="card-title">${cve.id}</h3>
                    <div class="tags-group">
                        ${kevHtml} ${severityHtml} ${epssHtml}
                        <span class="tag">PUB: ${pubDate}</span>
                    </div>
                </div>
                <p class="text-body">${cleanDesc}</p>
                <div class="card-footer" style="justify-content: space-between; align-items: center;">
                    <button class="watch-btn ${watchlist.some(w => w.id === cve.id) ? 'active' : ''}" data-id="${cve.id}" data-type="CVE">
                        ${watchlist.some(w => w.id === cve.id) ? '★ Watched' : '☆ Watch'}
                    </button>
                    <button class="btn btn-secondary read-cve-btn">Read Full Advisory &rarr;</button>
                </div>
            `;
            
            card.querySelector('.read-cve-btn').addEventListener('click', () => {
                loadCveDetails(cve, cleanDesc, severityHtml, epssHtml, kevHtml, pubDate);
            });

            
            card.querySelector('.watch-btn').addEventListener('click', () => {
                window.toggleWatchlist(cve.id, cve.id, 'CVE');
            });

            resultsContainer.appendChild(card);
        });

        if (matchCount === 0) {
            resultsContainer.innerHTML = `
                <div style="text-align: center; padding: 40px; color: var(--storacha-gray);">
                    <h3 style="margin-bottom: 8px;">No matches found</h3>
                    <p>Try adjusting your filters to see more results.</p>
                </div>`;
        }
    }

    
    function loadCveDetails(cve, description, severityHtml, epssHtml, kevHtml, pubDate) {
        resultsContainer.classList.add('hidden');
        articleContainer.classList.remove('hidden');
        
        document.getElementById('articleTitle').textContent = cve.id;
        const contentDiv = document.getElementById('articleContent');

        let metricsHtml = '';
        const metrics = cve.metrics || {};
        const cvssDataObj = metrics.cvssMetricV31?.[0] || metrics.cvssMetricV30?.[0] || metrics.cvssMetricV2?.[0];
        
        if (cvssDataObj && cvssDataObj.cvssData) {
            const d = cvssDataObj.cvssData;
            if (d.attackVector || d.accessVector) {
                metricsHtml = `
                    <h3>Exploitability Metrics</h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 24px; background: var(--storacha-light-gray); padding: 16px; border-radius: var(--radius-subtle);">
                        <div><strong>Attack Vector:</strong> <br>${d.attackVector || d.accessVector || 'N/A'}</div>
                        <div><strong>Complexity:</strong> <br>${d.attackComplexity || d.accessComplexity || 'N/A'}</div>
                        <div><strong>Privileges Required:</strong> <br>${d.privilegesRequired || d.authentication || 'N/A'}</div>
                        <div><strong>User Interaction:</strong> <br>${d.userInteraction || 'N/A'}</div>
                    </div>
                `;
            }
        }

        let kevDetailsHtml = '';
        if (cve.cisaExploitAdd) {
            kevDetailsHtml = `
                <div style="margin-bottom: 24px; background: rgba(190, 18, 60, 0.05); padding: 16px; border-left: 4px solid #BE123C; border-radius: 0 var(--radius-subtle) var(--radius-subtle) 0;">
                    <h3 style="margin-top: 0; color: #BE123C;">⚠️ CISA KEV Notice</h3>
                    <p style="margin-bottom: 0;"><strong>Vulnerability Name:</strong> ${cve.cisaVulnerabilityName || 'Unknown'}<br>
                    <strong>Added to Catalog:</strong> ${cve.cisaExploitAdd}<br>
                    <strong>Action Due:</strong> ${cve.cisaActionDue || 'Immediate'}<br>
                    <strong>Required Action:</strong> ${cve.cisaRequiredAction || 'Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.'}</p>
                </div>
            `;
        }

        let cpeHtml = '';
        if (cve.configurations && cve.configurations.length > 0) {
            let cpeList = [];
            cve.configurations.forEach(config => {
                if (config.nodes) {
                    config.nodes.forEach(node => {
                        if (node.cpeMatch) {
                            node.cpeMatch.forEach(match => {
                                const parts = match.criteria.split(':');
                                if (parts.length >= 5) {
                                    const vendor = parts[3].replace(/_/g, ' ');
                                    const product = parts[4].replace(/_/g, ' ');
                                    const version = parts[5] === '*' ? 'Any' : parts[5];
                                    
                                    let str = `<strong style="text-transform: capitalize;">${vendor} ${product}</strong> (Version: ${version})`;
                                    if (match.versionEndExcluding) str += ` <em>Prior to ${match.versionEndExcluding}</em>`;
                                    if (match.versionEndIncluding) str += ` <em>Up to ${match.versionEndIncluding}</em>`;
                                    cpeList.push(`<li>${str}</li>`);
                                }
                            });
                        }
                    });
                }
            });

            if (cpeList.length > 0) {
                const uniqueCpes = [...new Set(cpeList)].slice(0, 12);
                const moreTag = cpeList.length > 12 ? `<li style="list-style: none; margin-top: 8px;"><em>...and ${cpeList.length - 12} more configurations.</em></li>` : '';
                cpeHtml = `<h3>Known Affected Software</h3><ul>${uniqueCpes.join('')}${moreTag}</ul>`;
            }
        }

        const weaknesses = cve.weaknesses || [];
        let cweHtml = '';
        if (weaknesses.length > 0) {
            const cweItems = weaknesses.flatMap(w => {
                const desc = w.description?.find(d => d.lang === 'en');
                if (!desc || !desc.value) return [];
                
                const cweId = desc.value;
                
                
                if (cweId === 'NVD-CWE-noinfo' || cweId === 'NVD-CWE-Other') return [];

                
                const match = cweId.match(/CWE-(\d+)/);
                if (match) {
                    const num = match[1];
                    return `<a href="https://cwe.mitre.org/data/definitions/${num}.html" target="_blank" rel="noopener noreferrer" class="tag" style="background: var(--app-black); color: var(--app-white); text-decoration: none; cursor: pointer; transition: opacity 0.2s;">${cweId} &nearr;</a>`;
                }
                
                
                return `<span class="tag">${cweId}</span>`;
            });

            if (cweItems.length > 0) {
                
                const uniqueCwes = [...new Set(cweItems)];
                
                cweHtml = `
                    <h3>Vulnerability Type (CWE)</h3>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px;">
                        ${uniqueCwes.join('')}
                    </div>
                `;
            }
        }

        const refs = cve.references || [];
        let refsHtml = '';
        if (refs.length > 0) {
            const listItems = refs.map(r => `<li><a href="${r.url}" target="_blank" rel="noopener noreferrer">${r.url}</a></li>`).join('');
            refsHtml = `<h3>External Advisories & Patches</h3><ul>${listItems}</ul>`;
        }

        
        const pocHtml = `
            <div id="pocContainer" style="margin: 24px 0; padding: 16px; background: rgba(255, 69, 0, 0.05); border: 1px solid rgba(255, 69, 0, 0.2); border-radius: var(--radius-subtle); transition: all 0.3s ease;">
                <h3 style="margin-top: 0; color: var(--storacha-spicy); display: flex; align-items: center; gap: 8px;">
                    <span class="pulse-icon" style="position: static; margin-right: 4px;"></span> Searching for Public Exploits (PoCs)...
                </h3>
            </div>
        `;

        const html = `
            <div class="tags-group" style="margin-bottom: 24px;">
                ${kevHtml}
                ${severityHtml}
                ${epssHtml}
                <span class="tag">PUB: ${pubDate}</span>
            </div>
            
            <h3>Executive Summary</h3>
            <p>${description}</p>
            
            ${kevDetailsHtml}
            ${metricsHtml}
            ${pocHtml}
            ${cpeHtml}
            ${cweHtml}
            ${refsHtml}

            <div style="margin-top: 40px; padding-top: 24px; border-top: 1px solid var(--storacha-border);">
                <a href="https://nvd.nist.gov/vuln/detail/${cve.id}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary">
                    View Raw Record on NVD &rarr;
                </a>
            </div>
        `;

        if (typeof DOMPurify !== 'undefined') {
            contentDiv.innerHTML = DOMPurify.sanitize(html, { ADD_ATTR: ['target'] });
        } else {
            contentDiv.innerHTML = html;
        }

        window.scrollTo({ top: 0, behavior: 'smooth' });

        
        fetchAndRenderPoCs(cve.id, cve.references || []);
    }

    
    async function fetchAndRenderPoCs(cveId, nvdReferences) {
        const pocContainer = document.getElementById('pocContainer');
        if (!pocContainer) return;

        let pocLinksHtml = '';
        let foundPocs = 0;

        
        const nvdExploits = nvdReferences.filter(ref => ref.tags && ref.tags.includes('Exploit'));
        if (nvdExploits.length > 0) {
            pocLinksHtml += `<h4 style="margin-top: 12px; margin-bottom: 8px; font-size: 0.95rem;">Known Exploit References (NVD)</h4>
                             <ul style="margin-left: 20px; margin-bottom: 16px;">`;
            nvdExploits.slice(0, 4).forEach(exp => {
                foundPocs++;
                pocLinksHtml += `<li style="margin-bottom: 6px;"><a href="${exp.url}" target="_blank" rel="noopener noreferrer" style="color: var(--storacha-spicy); word-break: break-all;">${exp.url}</a></li>`;
            });
            pocLinksHtml += `</ul>`;
        }

        
        try {
            const githubRes = await fetch(`https://api.github.com/search/repositories?q=${cveId}+poc&sort=stars&order=desc&per_page=3`);
            if (githubRes.ok) {
                const data = await githubRes.json();
                if (data.items && data.items.length > 0) {
                    pocLinksHtml += `<h4 style="margin-top: 12px; margin-bottom: 8px; font-size: 0.95rem;">GitHub Repositories (Community PoCs)</h4>
                                     <ul style="list-style-type: none; margin-left: 0; padding: 0;">`;
                    data.items.forEach(repo => {
                        foundPocs++;

                        const repoUrl = repo.html_url.replace(/"/g, '&quot;');
                        const repoName = repo.full_name.replace(/</g, '&lt;').replace(/>/g, '&gt;');
                        const repoDesc = (repo.description || 'No description provided.').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                        
                        pocLinksHtml += `
                            <li style="margin-bottom: 12px; background: var(--storacha-white); padding: 12px; border: 1px solid var(--storacha-border); border-radius: var(--radius-sharp);">
                                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                                    <a href="${repoUrl}" target="_blank" rel="noopener noreferrer" style="font-weight: 600; color: var(--storacha-spicy); text-decoration: none;">${repoName}</a>
                                    <span class="tag" style="font-size: 0.7rem; background: var(--storacha-light-gray); color: var(--storacha-black);">⭐ ${repo.stargazers_count}</span>
                                </div>
                                <p style="font-size: 0.85rem; color: var(--storacha-gray); margin: 0;">${repoDesc}</p>
                            </li>
                        `;
                    });
                    pocLinksHtml += `</ul>`;
                }
            }
        } catch (err) {
            console.warn('GitHub API fetch failed for PoCs', err);
        }


        if (foundPocs > 0) {
            pocContainer.innerHTML = `
                <h3 style="margin-top: 0; color: #BE123C; display: flex; align-items: center; gap: 8px;">
                    ⚠️ Proof of Concept / Exploits Available
                </h3>
                ${pocLinksHtml}
            `;
            pocContainer.style.background = 'rgba(190, 18, 60, 0.05)';
            pocContainer.style.borderColor = '#BE123C';
        } else {
            pocContainer.innerHTML = `
                <h3 style="margin-top: 0; color: var(--storacha-gray); display: flex; align-items: center; gap: 8px;">
                    🛡️ No Public PoCs Found
                </h3>
                <p style="margin: 0; font-size: 0.9rem; color: var(--storacha-gray);">We scanned NVD and GitHub, but no public exploit code was found at this time.</p>
            `;
            pocContainer.style.background = 'var(--storacha-light-gray)';
            pocContainer.style.borderColor = 'var(--storacha-border)';
        }
    }


    async function fetchMalware(query) {
        statusMessage.textContent = 'Querying MITRE ATT&CK threat intelligence database...';
        try {

            if (!mitreDataCache) {
                statusMessage.textContent = 'Downloading MITRE ATT&CK dataset (first load takes a moment)...';
                const response = await fetch('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json');
                
                if (!response.ok) throw new Error(`GitHub API returned status: ${response.status}`);
                
                const data = await response.json();
                

                mitreDataCache = data.objects.filter(obj => 
                    obj.type === 'malware' || obj.type === 'tool' || obj.type === 'intrusion-set'
                );
            }
            
            statusMessage.classList.add('hidden');
            statusMessage.classList.remove('pulse-text');
            
            const q = query.toLowerCase();
            

            const results = mitreDataCache.filter(obj => 
                (obj.name && obj.name.toLowerCase().includes(q)) || 
                (obj.x_mitre_aliases && obj.x_mitre_aliases.some(alias => alias.toLowerCase().includes(q)))
            );

            if (results.length > 0) {
                resultsContainer.innerHTML = ''; 
                
                results.forEach((item, index) => {
                    const card = document.createElement('div');
                    card.className = 'card fade-in-up'; 
                    card.style.animationDelay = `${(index % 10) * 0.05}s`;
                    

                    let cleanDesc = item.description ? item.description.replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1') : 'No description available.';
                    if (typeof DOMPurify !== 'undefined') cleanDesc = DOMPurify.sanitize(cleanDesc);
                    const snippet = cleanDesc.length > 250 ? cleanDesc.substring(0, 250) + '...' : cleanDesc;
                    
                    let typeLabel = item.type.toUpperCase();
                    if (typeLabel === 'INTRUSION-SET') typeLabel = 'THREAT ACTOR';

                    card.innerHTML = `
                        <div class="card-header">
                            <h3 class="card-title">${item.name}</h3>
                            <div class="tags-group">
                                <span class="tag tag-critical" style="background: var(--app-spicy); border-color: var(--app-spicy); color: white;">${typeLabel}</span>
                                ${item.x_mitre_platforms ? `<span class="tag">${item.x_mitre_platforms[0]}${item.x_mitre_platforms.length > 1 ? ' +' : ''}</span>` : ''}
                            </div>
                        </div>
                        <p class="text-body">${snippet}</p>
                        <div class="card-footer">
                            <button class="btn btn-secondary read-malware-btn">
                                Read Threat Profile &rarr;
                            </button>
                        </div>
                    `;
                    
                    const readBtn = card.querySelector('.read-malware-btn');
                    readBtn.addEventListener('click', () => {
                        loadMalwareArticle(item);
                    });

                    resultsContainer.appendChild(card);
                });
            } else {
                statusMessage.classList.remove('hidden', 'pulse-text');
                statusMessage.textContent = `No malware or threat actor records found for "${query}".`;
            }
        } catch (error) {
            handleError(error);
        }
    }

    function loadMalwareArticle(item) {
        resultsContainer.classList.add('hidden');
        articleContainer.classList.remove('hidden');
        
        document.getElementById('articleTitle').textContent = item.name;
        const contentDiv = document.getElementById('articleContent');
        
        let typeLabel = item.type.toUpperCase();
        if (typeLabel === 'INTRUSION-SET') typeLabel = 'THREAT ACTOR (APT)';


        let aliasesHtml = '';
        if (item.x_mitre_aliases && item.x_mitre_aliases.length > 0) {
            aliasesHtml = `<h3>Known Aliases</h3><p>${item.x_mitre_aliases.join(', ')}</p>`;
        }

        let platformsHtml = '';
        if (item.x_mitre_platforms && item.x_mitre_platforms.length > 0) {
            platformsHtml = `<h3>Targeted Platforms</h3><p>${item.x_mitre_platforms.join(', ')}</p>`;
        }

        let externalRefsHtml = '';
        if (item.external_references && item.external_references.length > 0) {
            const refsList = item.external_references.map(ref => {
                if (ref.url) return `<li style="margin-bottom: 6px;"><a href="${ref.url}" target="_blank" rel="noopener noreferrer" style="color: var(--app-spicy); word-break: break-all;">${ref.source_name || ref.url}</a></li>`;
                return '';
            }).filter(Boolean).slice(0, 15).join(''); 
            
            if (refsList) externalRefsHtml = `<h3>External Security Writeups</h3><ul style="margin-left: 20px;">${refsList}</ul>`;
        }


        let formattedDesc = item.description || 'No detailed description provided.';
        formattedDesc = formattedDesc.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" style="color: var(--app-spicy);">$1</a>');
        formattedDesc = formattedDesc.replace(/\n\n/g, '</p><p>').replace(/\n/g, '<br>');
        
        const cleanDesc = typeof DOMPurify !== 'undefined' ? DOMPurify.sanitize(`<p>${formattedDesc}</p>`, { ADD_ATTR: ['target'] }) : `<p>${formattedDesc}</p>`;


        const html = `
            <div class="tags-group" style="margin-bottom: 24px;">
                <span class="tag tag-critical" style="background: var(--app-spicy); border-color: var(--app-spicy); color: white;">${typeLabel}</span>
                <span class="tag">MITRE ID: ${item.external_references?.[0]?.external_id || 'N/A'}</span>
            </div>
            
            <h3>Executive Summary</h3>
            <div class="wiki-content text-body">${cleanDesc}</div>
            
            ${aliasesHtml}
            ${platformsHtml}
            ${externalRefsHtml}
            
            <div style="margin-top: 40px; padding-top: 24px; border-top: 1px solid var(--app-border);">
                <a href="${item.external_references?.[0]?.url || 'https://attack.mitre.org/'}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary">
                    View Official Record on MITRE ATT&CK &rarr;
                </a>
            </div>
        `;

        contentDiv.innerHTML = html;
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    backToResultsBtn.addEventListener('click', () => {
        articleContainer.classList.add('hidden');
        resultsContainer.classList.remove('hidden');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    function handleError(error) {
        console.error(error);
        statusMessage.classList.remove('pulse-text');
        statusMessage.style.color = 'var(--storacha-red)';
        statusMessage.textContent = `System Error: ${error.message}`;
    }

    async function initHotFeed() {
        const feedContainer = document.getElementById('liveFeedContent');
        
        const date = new Date();
        date.setHours(date.getHours() - 24);
        const timeStamp = date.toISOString().split('.')[0]; 

        const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${timeStamp}`;

        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`NVD API Status: ${response.status}`);
            }

            const data = await response.json();

            if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
                feedContainer.innerHTML = '<p class="status-text">No new threats in the last 24h.</p>';
                return;
            }

            const latestCves = data.vulnerabilities.slice(0, 10);
            feedContainer.innerHTML = ''; 

            latestCves.forEach(item => {
                const cve = item.cve;
                const desc = cve.descriptions.find(d => d.lang === 'en')?.value || "No description available.";
                
                if (!notifiedFeedIds.includes(cve.id)) {

                    const isWatched = watchlist.some(w => w.id === cve.id);
                    

                    sendDiscordAlert(
                        ` NEW ALERT: ${cve.id}`, 
                        `${isWatched ? '**[WATCHLIST ITEM UPDATED]**\n\n' : ''}${desc.substring(0, 300)}...`, 
                        `https://nvd.nist.gov/vuln/detail/${cve.id}`
                    );


                    notifiedFeedIds.push(cve.id);

                    if (notifiedFeedIds.length > 100) notifiedFeedIds.shift();
                    localStorage.setItem('tish_notified', JSON.stringify(notifiedFeedIds));
                }
                
                const itemEl = document.createElement('div');
                itemEl.className = 'feed-item fade-in-up';
                itemEl.innerHTML = `
                    <span class="cve-id">${cve.id}</span>
                    <p class="cve-desc">${desc}</p>
                `;
                feedContainer.appendChild(itemEl);
            });

        } catch (err) {
            console.error("Hot Feed Error:", err);
            feedContainer.innerHTML = `
                <p class="status-text" style="color: var(--storacha-gray); font-size: 0.7rem;">
                    Feed temporarily throttled by NVD. <br> Retrying shortly...
                </p>`;
        }
    }


    async function sendDiscordAlert(title, description, url, color = 16729344) {
        if (!webhookUrl) return;

        const payload = {
            username: "TISH Alerts",
            avatar_url: "https://i.imgur.com/your-tish-logo.png", 
            embeds: [{
                title: title,
                description: description,
                url: url,
                color: color, 
                timestamp: new Date().toISOString(),
                footer: { text: "Threat Intelligence, Served Hot." }
            }]
        };

        try {
            await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } catch (err) {
            console.error("Failed to send Discord webhook", err);
        }
    }


    window.toggleWatchlist = function(id, title, type) {
        const exists = watchlist.find(item => item.id === id);
        if (exists) {
            watchlist = watchlist.filter(item => item.id !== id);
        } else {
            watchlist.push({ id, title, type, addedAt: new Date().toISOString() });
        }
        localStorage.setItem('tish_watchlist', JSON.stringify(watchlist));
        document.getElementById('watchCount').textContent = watchlist.length;
        renderWatchlist();


        const watchBtns = document.querySelectorAll(`.watch-btn[data-id="${id}"]`);
        watchBtns.forEach(btn => {
            const isWatched = watchlist.some(w => w.id === id);
            if(isWatched) {
                btn.classList.add('active');
                btn.textContent = '★ Watched';
            } else {
                btn.classList.remove('active');
                btn.textContent = '☆ Watch';
            }
        });
    };


    const modal = document.getElementById('alertsModal');
    document.getElementById('navWatchlistBtn').addEventListener('click', () => {
        document.getElementById('webhookInput').value = webhookUrl;
        renderWatchlist();
        modal.classList.remove('hidden');
    });

    document.getElementById('closeModalBtn').addEventListener('click', () => modal.classList.add('hidden'));

    document.getElementById('saveWebhookBtn').addEventListener('click', () => {
        const val = document.getElementById('webhookInput').value.trim();
        webhookUrl = val;
        localStorage.setItem('tish_webhook', val);
        
        if(val) {
            sendDiscordAlert("🟢 TISH Webhook Connected", "Your TISH dashboard is now hooked up to this channel. You will receive alerts for new CVEs on the live feed and updates to tracked items.", "https://nvd.nist.gov", 3066993);
            alert("Webhook saved and test fired!");
        } else {
            alert("Webhook removed.");
        }
    });

    function renderWatchlist() {
        const container = document.getElementById('watchlistContainer');
        document.getElementById('watchCount').textContent = watchlist.length;
        if (watchlist.length === 0) {
            container.innerHTML = '<p class="text-body" style="font-size:0.9rem;">Your watchlist is empty.</p>';
            return;
        }

        container.innerHTML = watchlist.map(item => `
            <div class="feed-item" style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <span class="cve-id" style="font-size:0.9rem;">${item.id}</span>
                    <span class="tag">${item.type}</span>
                </div>
                <button class="btn-text" onclick="window.toggleWatchlist('${item.id}', '', '')" style="color:var(--app-spicy); font-size:1.2rem;">&times;</button>
            </div>
        `).join('');
    }


    document.getElementById('watchCount').textContent = watchlist.length;
});