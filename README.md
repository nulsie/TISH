# TISH: Threat Intelligence, Served Hot

TISH is a fully client-side, purely static threat intelligence dashboard. It requires **zero backend infrastructure**. It runs entirely in your browser, hitting public APIs, caching data in `localStorage`, and keeping your searches entirely localized. 

It handles:
1.  **Vulnerability (CVE) Search:** Cross-referencing NVD with EPSS (Exploit Prediction Scoring System) and CISA KEV (Known Exploited Vulnerabilities).
2.  **PoC Hunting:** Dynamically scraping the GitHub API for community exploits based on CVE IDs.
3.  **Malware & Actor Profiling:** Parsing the raw MITRE ATT&CK dataset.
4.  **SBOM Scanning:** Batch-querying Google's OSV.dev database to find dependency vulnerabilities.
5.  **Automated Alerting:** Pushing live NVD feed updates to Discord via Webhooks.

---

## Table of Contents

### 1. [Architecture & The Tech Stack](#architecture-&-the-tech-stack)

### 2. [Core Modules: Under the Hood](#core-modules:-under-the-hood)

###### 2.1 [The Search Engine & EPSS Enrichment](#the-search-engine-&-epss-enrichment)

###### 2.2 [The PoC Hunter](#the-poc-hunter)

###### 2.3 [The SBOM Scanner](#the-sbom-scanner)

###### 2.4 [Discord Webhook Alerting](#discord-webhook-alerting)

### 3. [Local Deployment](#local-deployment)

###### 3.1 [Known Limitations to keep in mind:](#known-limitations-to-keep-in-mind)

### 5. [License](#license)

---

## Architecture & The Tech Stack

Because TISH is essentially a giant API aggregator wrapped in a spicy UI, the stack is delightfully simple:
* **Vanilla HTML/CSS/JS:** No React, no Vue, no build steps. Just raw, unadulterated JavaScript.
* **DOMPurify:** Absolutely critical. Since we inject raw descriptions and markdown from NVD and MITRE into the DOM, DOMPurify prevents XSS injections.
* **Data Sources:**
    * NVD API 2.0 (`services.nvd.nist.gov`)
    * FIRST.org EPSS API (`api.first.org`)
    * Google OSV API (`api.osv.dev`)
    * GitHub Search API (`api.github.com`)
    * MITRE ATT&CK Enterprise JSON (via raw.githubusercontent)

---

## Core Modules: Under the Hood

### 1. The Search Engine & EPSS Enrichment

When you search for a CVE or product, TISH doesn't just return NVD data. It fetches the NVD payload and then fires off a secondary request to FIRST.org to map EPSS scores to the results. This is what gives you the "probability of exploitation."

Here's how we map the NVD output to EPSS in real-time:

```javascript
// Fetch NVD Data
const apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=50`;
const response = await fetch(apiUrl);
const data = await response.json();

// Extract all CVE IDs from the results to batch-query EPSS
const cveIds = data.vulnerabilities.map(item => item.cve.id).join(',');

// Hit FIRST.org for the exploitability scores
const epssResponse = await fetch(`https://api.first.org/data/v1/epss?cve=${cveIds}`);
const epssData = await epssResponse.json();

// Map it to a localized cache for rendering
epssData.data.forEach(item => {
    currentEpssDataMap[item.cve] = {
        score: (parseFloat(item.epss) * 100).toFixed(2), // Convert to percentage
        percentile: (parseFloat(item.percentile) * 100).toFixed(0)
    };
});
```

### 2. The PoC Hunter

NVD references are great, but finding actual exploit code is better. When you open a CVE card, TISH automatically hits the GitHub Search API looking for repositories matching the CVE ID + "poc".

> **Note:** We sort by stars so you don't get junk repos with empty `README.md` files.

```javascript
// Inside fetchAndRenderPoCs()
const githubRes = await fetch(`https://api.github.com/search/repositories?q=${cveId}+poc&sort=stars&order=desc&per_page=3`);
const data = await githubRes.json();

if (data.items && data.items.length > 0) {
    data.items.forEach(repo => {
        // Sanitize heavily before rendering
        const repoUrl = repo.html_url.replace(/"/g, '&quot;');
        const repoName = repo.full_name.replace(/</g, '&lt;').replace(/>/g, '&gt;');
        const repoDesc = (repo.description || 'No description').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        
        // Render to UI...
    });
}
```

### 3. The SBOM Scanner

This is arguably the heaviest lifter in the app. It takes messy input (like a raw `package.json`, a Python `requirements.txt`, or just text dumps), parses out the package names and versions using Regex and JSON parsing, and throws them at the OSV.dev batch API.

Here is the parsing logic that tries to guess what the hell the user just pasted into the textarea:

```javascript
function parseManifest(raw) {
    let deps = [];
    
    // Attempt 1: Try parsing it as a valid JSON manifest (e.g., package.json)
    try {
        const json = JSON.parse(raw);
        const allDeps = { ...(json.dependencies || {}), ...(json.devDependencies || {}) };
        
        for (const [name, version] of Object.entries(allDeps)) {
            const cleanVersion = version.replace(/[\^~><=xX*]/g, '').trim(); // Strip npm operators
            if (cleanVersion) deps.push({ name, version: cleanVersion });
        }
        if (deps.length > 0) return deps;
    } catch (e) { /* Not JSON, move to text parsing */ }

    // Attempt 2: Line-by-line parsing for requirements.txt or raw strings
    const lines = raw.split('\n');
    lines.forEach(line => {
        line = line.trim();
        if (!line || line.startsWith('#') || line.startsWith('//')) return;

        // Matches Python style: requests==2.25.1 or requests>=2.0
        let match = line.match(/^([a-zA-Z0-9_\-\.]+)[=!><~]+([0-9\.]+.*)/);
        if (match) {
            deps.push({ name: match[1], version: match[2].replace(/[\^~><=]/g, '').trim() });
            return;
        }

        // Matches generic colon style: lodash:4.17.20
        match = line.match(/^([a-zA-Z0-9_\-\.]+):([0-9\.]+.*)/);
        if (match) {
            deps.push({ name: match[1], version: match[2].trim() });
        }
    });

    return deps;
}
```

Once parsed, we map the array into the specific payload structure OSV expects and fire the batch query:

```javascript
const queries = packages.map(pkg => ({
    package: { name: pkg.name, ecosystem: ecosystem },
    version: pkg.version
}));

const response = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queries })
});
```

### 4. Discord Webhook Alerting

TISH polls the NVD API every 10 minutes (`setInterval(initHotFeed, 600000);`) for CVEs published in the last 24 hours. It checks these against your `localStorage` watchlist and notified array. If a new threat drops, it formats a Discord Embed and fires it to your webhook.

```javascript
async function sendDiscordAlert(title, description, url, color = 16729344) {
    if (!webhookUrl) return; // webhookUrl is pulled from localStorage

    const payload = {
        username: "TISH Alerts",
        embeds: [{
            title: title,
            description: description,
            url: url,
            color: color, // Defaults to TISH Spicy Orange
            timestamp: new Date().toISOString(),
            footer: { text: "Threat Intelligence, Served Hot." }
        }]
    };

    await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
}
```

---

## Local Deployment

Because there's no build process, running this locally is laughably easy.

1.  **Clone it:** `git clone <your-repo-url>`
2.  **Serve it:** You cannot just double-click the `index.html` file because CORS policies will block the API requests if served over the `file://` protocol. You need a local server.
    * If you have Python: `python -m http.server 8000`
    * If you have Node: `npx serve .`
    * If you use VS Code: Use the "Live Server" extension.
3.  **Open it:** Navigate to `http://localhost:8000`

### Known Limitations to keep in mind
* **NVD Rate Limits:** The NVD API is notorious for throttling unauthenticated requests. If you smash the search button, you will get a `403 Forbidden`. TISH handles this gracefully in the UI, but if you fork this for heavy production use, you'll want to append an `apiKey` header to the NVD fetch requests.
* **MITRE Payload Size:** The MITRE ATT&CK JSON file is massive. TISH downloads it once per session and caches it in the `mitreDataCache` variable. The first search in the "Malware and Actors" tab might take a couple of seconds.
* **The Alerting System:** Because the entire application is fronte-end, it wouldn't be able to send feed during rest by you just deploying it as it is, but it still could be able to send even now if you're using a different app while TISH is also active. But for 24/7 deployment, you should use a simple Node.js script.

---

## License

TISH is licensed under the **GNU General Public License v3.0**. 

Basically: You can fork it, tweak it, host it, and share it. Just keep it open source, state your changes, and give a shout-out to the original project. Stay spicy.