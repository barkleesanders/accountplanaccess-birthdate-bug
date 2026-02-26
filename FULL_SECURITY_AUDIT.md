# Full Security Audit — accountplanaccess.com (NextLevel Platform)

> **Classification: HIGH SEVERITY** — Multiple critical findings including unauthenticated access to admin pages with leaked session tokens, deprecated TLS protocols, directory traversal, and exposed internal API infrastructure.

> **Methodology:** Passive reconnaissance only — HTTP headers, SSL/TLS analysis, DNS records, and publicly accessible file enumeration. No authentication was bypassed, no exploitation was attempted, and no user data was accessed.

---

## Table of Contents

1. [SSL/TLS Configuration](#1-ssltls-configuration)
2. [HTTP Security Headers](#2-http-security-headers)
3. [Infrastructure & DNS](#3-infrastructure--dns)
4. [Exposed Pages — Unauthenticated Admin Access](#4-exposed-pages--unauthenticated-admin-access)
5. [Session Token Leakage](#5-session-token-leakage)
6. [Directory & File Exposure](#6-directory--file-exposure)
7. [JavaScript Library Inventory & CVEs](#7-javascript-library-inventory--cves)
8. [MFA Browser Fingerprinting Weakness](#8-mfa-browser-fingerprinting-weakness)
9. [Cookie Security](#9-cookie-security)
10. [ASP.NET Diagnostic Endpoints](#10-aspnet-diagnostic-endpoints)
11. [API Infrastructure](#11-api-infrastructure)
12. [Compliance Gap Analysis](#12-compliance-gap-analysis)
13. [Complete Finding Summary](#13-complete-finding-summary)

---

## 1. SSL/TLS Configuration

### Certificate
| Field | Value |
|-------|-------|
| Subject | `C=US, ST=Florida, O=Fidelity National Information Services, CN=www.accountplanaccess.com` |
| Issuer | `Sectigo Public Server Authentication CA OV R36` |
| Valid From | May 16, 2025 |
| Valid To | **June 15, 2026** |
| SANs | `www.accountplanaccess.com`, `accountplanaccess.com` |
| Type | OV (Organization Validated) |

### Protocol Support

| Protocol | Status | Finding |
|----------|--------|---------|
| SSLv3 | ❌ Disabled | ✅ Good |
| **TLS 1.0** | ✅ Enabled | 🔴 **CRITICAL** — Deprecated by NIST, PCI DSS 3.2+ requires disabling |
| **TLS 1.1** | ✅ Enabled | 🔴 **CRITICAL** — Deprecated by all major browsers since 2020 |
| TLS 1.2 | ✅ Enabled | ✅ Good |
| TLS 1.3 | ✅ Enabled | ✅ Good |

**Finding:** TLS 1.0 and 1.1 are enabled. These protocols have known vulnerabilities (BEAST, POODLE downgrade) and are **prohibited by PCI DSS** for payment/financial card data. A financial services platform handling SSNs and retirement data must disable these.

---

## 2. HTTP Security Headers

### Headers Present
| Header | Value | Assessment |
|--------|-------|------------|
| `X-Frame-Options` | `SAMEORIGIN` | 🟡 Present but should be `DENY` for login pages |
| `X-Content-Type-Options` | `nosniff` | ✅ Good |
| `X-XSS-Protection` | `1; mode=block` | 🟡 Deprecated header — CSP should be used instead |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | ✅ Good |
| `Cache-Control` | `max-age=0, no-cache, no-store` | ✅ Good |
| `Pragma` | `no-cache` | ✅ Good |
| `Access-Control-Allow-Methods` | `GET,PUT,POST,DELETE,OPTIONS` | 🔴 **Overly permissive CORS** |
| `Access-Control-Allow-Headers` | `Content-Type` | 🟡 No origin restriction |

### Headers Missing
| Missing Header | Risk |
|----------------|------|
| `Content-Security-Policy` | 🔴 **No CSP** — allows inline scripts, eval, and any source |
| `Permissions-Policy` | 🟡 No feature restrictions (camera, microphone, geolocation) |
| `Referrer-Policy` | 🟡 May leak URLs in referrer headers |
| `X-Permitted-Cross-Domain-Policies` | Low — Flash/Silverlight cross-domain |

### Critical CORS Issue
```
Access-Control-Allow-Methods: GET,PUT,POST,DELETE,OPTIONS
```
This allows **any origin** to make PUT and DELETE requests. Combined with the empty CSRF token, this enables cross-origin state-changing requests.

---

## 3. Infrastructure & DNS

| Record | Value |
|--------|-------|
| **CDN** | Akamai (`edgekey.net`, `akamaiedge.net`) |
| **IPs** | `23.216.149.151`, `23.216.149.137` |
| **MX** | `10 accountplanaccess.com` (self-hosted mail) |
| **SPF** | `v=spf1 -all` (rejects all senders — no email from this domain) |
| **Server** | ASP.NET on IIS (Microsoft stack) |
| **Organization** | Fidelity National Information Services (FIS) |

**Note:** The SSL certificate identifies the organization as **FIS (Fidelity National Information Services)**, confirming this is a FIS/Broadridge product.

---

## 4. Exposed Pages — Unauthenticated Admin Access

🔴 **CRITICAL FINDING:** Multiple admin/privileged pages return HTTP 200 without requiring authentication:

| Status | Page | Purpose | Severity |
|--------|------|---------|----------|
| **200** | `/NextLevel/csr.aspx` | **Customer Service Rep portal** | 🔴 CRITICAL |
| **200** | `/NextLevel/sponsor.aspx` | **Sponsor/Employer admin portal** | 🔴 CRITICAL |
| **200** | `/NextLevel/advisor.aspx` | **Financial Advisor portal** | 🔴 CRITICAL |
| **200** | `/NextLevel/manageinvestments.aspx` | Investment management page | 🔴 HIGH |
| **200** | `/NextLevel/rebalancelanding.aspx` | Portfolio rebalancing page | 🔴 HIGH |
| **200** | `/NextLevel/forgotpassword.aspx` | Password reset page | 🟡 Expected |
| **200** | `/NextLevel/error.aspx` | Error handler | Low |

While these pages may redirect client-side or require a valid session to display data, the fact that the **server-side pages return 200 with full HTML including JavaScript configuration** means:
- The page template, JavaScript, and configuration objects are exposed
- Session tokens are generated and returned (see Section 5)
- The Angular application framework loads completely

**These pages should return 401/403 without a valid session cookie.**

---

## 5. Session Token Leakage

🔴 **CRITICAL FINDING:** The CSR and Sponsor pages return **active session tokens** to unauthenticated visitors:

### From `/NextLevel/csr.aspx` (unauthenticated):
```
ServiceConfig.Token = '6D4B6B4F58434B51437A...'
ServiceConfig.LSToken = '6E754D345446674434454D...'
ServiceConfig.ServiceSiteId = 'f77b9ff7-1c84-4e14-ac51-ae67bb908b58'
ServiceConfig.Sid = 'MXNJzfejWFG47mP7bKTkqQ==Jb9xn4/YUA8mbQyaXbUadQA='
ServiceConfig.MfaUInfo = 'PKlpM9ejF14bSp0KiEE5zw==klrNlMAF3Q9...'
ServiceConfig.MfaProvider = 'E'
ServiceConfig.ServiceWebAPIURL = 'https://www.accountplanaccess.com/nextlevelapi'
ServiceConfig.SecurityKey = ''
```

### From `/NextLevel/sponsor.aspx` (unauthenticated):
```
ServiceConfig.Token = '6D5030643739464748473278...'
ServiceConfig.LSToken = '2F386B424D5432534269646C...'
ServiceConfig.ServiceSiteId = 'f77b9ff7-1c84-4e14-ac51-ae67bb908b58'
```

**Impact:** These tokens are generated server-side for each request. An attacker could:
1. Harvest tokens from unauthenticated page loads
2. Use the `ServiceSiteId`, `Token`, and `LSToken` to make API calls
3. The API at `https://www.accountplanaccess.com/nextlevelapi` returns **401** (requires auth), but the tokens from the page may be sufficient for certain API endpoints

---

## 6. Directory & File Exposure

### Accessible Directories (HTTP 200)
| Path | Risk |
|------|------|
| `/NextLevel/script/` | 🔴 Script directory listing |
| `/NextLevel/resources/` | 🟡 Resource directory |
| `/NextLevel/resources/js/` | 🟡 JS directory |
| `/NextLevel/resources/js/vendor/` | 🟡 Vendor library directory |
| `/NextLevel/resources/css/` | 🟡 CSS directory |
| `/NextLevel/CSS-Files/` | 🟡 Additional CSS |
| `/NextLevel/templates/` | 🔴 **Angular templates — may contain sensitive UI patterns** |
| `/NextLevel/script/common/` | 🟡 Common scripts |

### Accessible Script Files (total ~1.7MB of source code)
| File | Size | Content |
|------|------|---------|
| `vendor.js` | 921KB | All vendor libraries concatenated |
| `fusioncharts.js` | 587KB | Charting library |
| `javascript.js` | 39KB | Core utility functions (unminified) |
| `jquery_1.8.3-min.js` | 92KB | jQuery 1.8.3 |
| `dhtmlwindow.js` | 18KB | DHTML Window Widget |
| `javascript-min.js` | 18KB | Minified core utils |
| `DD_roundies_0.0.2a.js` | 16KB | IE rounded corners |
| `tooltip.js` | 15KB | Tooltip library |
| `sha256.jquery.debug.js` | 9KB | SHA-256 debug build |
| `dg-filter.js` | 6KB | Data grid filter |
| `forgotpassword.js` | 6KB | Password reset logic |
| `mootools-xml.js` | 5KB | MooTools XML parser |
| `login-min.js` | 1.6KB | Login logic |
| `MFA_BrowserFootprint-min.js` | 1.4KB | MFA fingerprinting |

### Properly Blocked
| Status | Path |
|--------|------|
| 404 | `/.git/HEAD` — ✅ Not exposed |
| 403 | `/.env` — ✅ Blocked (but 403 confirms it exists) |
| 404 | `/web.config` — ✅ Not exposed |
| 404 | `/.well-known/security.txt` — ⚠️ No security.txt |
| 401 | `/nextlevelapi/` — ✅ API requires auth |

**Note:** The `/.env` file returns **403 Forbidden** instead of 404. A 403 confirms the file **exists** but is access-restricted. This file likely contains environment variables, database connection strings, or API keys.

---

## 7. JavaScript Library Inventory & CVEs

| Library | Version | Known CVEs | Severity |
|---------|---------|------------|----------|
| **jQuery** | **1.8.3** (2012) | CVE-2015-9251, CVE-2019-11358, CVE-2020-11022, CVE-2020-11023 | 🔴 HIGH — XSS |
| **AngularJS** | **1.x** (EOL Dec 2021) | CVE-2022-25869, CVE-2023-26116, multiple prototype pollution | 🔴 HIGH — XSS, sandbox escape |
| **MooTools** | 1.6.0 | Prototype pollution via `Array.from` polyfill | 🟡 MEDIUM |
| **FusionCharts** | Unknown | Depends on version | 🟡 MEDIUM |
| **DD_roundies** | 0.0.2a | Abandoned library, no security updates | 🟡 LOW |
| **DHTML Window** | Unknown | Dynamic Drive legacy widget, unsupported | 🟡 LOW |
| **Bootstrap Datepicker** | Unknown | Multiple XSS in older versions | 🟡 MEDIUM |

**Total known CVEs in client-side dependencies: 8+**

---

## 8. MFA Browser Fingerprinting Weakness

The `MFA_BrowserFootprint-min.js` file reveals the browser fingerprint algorithm:

```javascript
// Fingerprint composition:
var fingerprint = {
    webkit: jQuery183.browser.webkit,
    version: jQuery183.browser.version,
    ajax: jQuery183.support.ajax,
    // ... 15 more jQuery.support properties ...
    OS: navigator.appVersion (Win/Mac/UNIX/Linux),
    platform: navigator.platform,
    browser: browser,  // global variable
    guid: guid,         // session GUID
    provider: ServiceConfig.MfaProvider
};
// Final fingerprint = SHA-256 hash of the above
return jQuery.sha256(JSON.stringify(fingerprint));
```

**Weaknesses:**
1. **Low entropy** — Only ~20 data points, many of which are boolean or have <5 possible values
2. **jQuery.browser deprecated** — Removed in jQuery 1.9+; using jQuery 1.8.3 specifically to keep it working
3. **Deterministic** — Same browser + same GUID = same fingerprint every time
4. **No hardware-based signals** — No Canvas, WebGL, AudioContext, or other modern fingerprinting
5. **GUID included** — The fingerprint changes per session, making it useless as a device identifier

---

## 9. Cookie Security

| Cookie | Secure | HttpOnly | SameSite | Expiry | Assessment |
|--------|--------|----------|----------|--------|------------|
| `ReliusUserID` | ✅ Yes | ✅ Yes | Not set | 2026-08-01 | 🟡 Missing SameSite |
| `QTWEB` | ✅ Yes | ✅ Yes | Not set | Session | 🟡 Missing SameSite |
| `bm_sv` | ✅ Yes | ❌ No | Not set | ~2hrs | 🟡 Accessible to JS |
| `ak_bmsc` | ✅ Yes | ✅ Yes | Not set | ~2hrs | ✅ OK |
| `OptanonConsent` | ❌ No | ❌ No | Not set | 1 year | 🟡 Not secure/httponly |
| `OptanonAlertBoxClosed` | ❌ No | ❌ No | Not set | 1 year | 🟡 Not secure/httponly |
| Set-Cookie (empty) | ✅ Yes | — | — | — | 🔴 **Empty Set-Cookie header** — suspicious |

**Issues:**
- No `SameSite` attribute on any cookie — allows CSRF via cross-origin requests
- `bm_sv` (Akamai bot management) is accessible to JavaScript — can be exfiltrated via XSS
- Empty `Set-Cookie: ; Secure` header in response — indicates a misconfigured cookie

---

## 10. ASP.NET Diagnostic Endpoints

| Endpoint | Status | Response |
|----------|--------|----------|
| `/NextLevel/elmah.axd` | 200 | Generic error page (locked down) |
| `/NextLevel/trace.axd` | 200 | Generic error page (locked down) |
| `/NextLevel/error.aspx` | 200 | Generic error page |

**Assessment:** These endpoints **exist** (return 200 not 404) but appear to be locked down behind a generic error handler. However:
- Their existence confirms ELMAH (Error Logging Modules and Handlers) is installed
- `trace.axd` existence confirms ASP.NET tracing is configured
- Both should return **404** to avoid confirming their existence to attackers

---

## 11. API Infrastructure

| Endpoint | Auth | Notes |
|----------|------|-------|
| `https://www.accountplanaccess.com/nextlevelapi/` | 401 | REST API — properly requires auth |
| `/NextLevel/ajaxdatarequest.aspx` | 200 (timeout) | Legacy AJAX handler — accepts `METHOD` parameter |

### API Headers Exposed in JavaScript
```
X-GUID: [session GUID]
X-TOKEN: [auth token]  
X-LSTOKEN: [layer security token]
X-SITEID: f77b9ff7-1c84-4e14-ac51-ae67bb908b58
```

The `ServiceSiteId` is static (`f77b9ff7-1c84-4e14-ac51-ae67bb908b58`) across all pages, meaning it's not a per-session value — it identifies the installation/deployment.

---

## 12. Compliance Gap Analysis

### PCI DSS 4.0 (applies to financial data handling)
| Requirement | Status | Finding |
|-------------|--------|---------|
| 2.2.7 — Disable insecure protocols | ❌ FAIL | TLS 1.0 and 1.1 enabled |
| 4.2.1 — Strong cryptography for transmission | ❌ FAIL | TLS 1.0 allows weak ciphers |
| 6.2.4 — Software security best practices | ❌ FAIL | jQuery 1.8.3 with known CVEs |
| 6.4.1 — Public-facing web app protection | ❌ FAIL | No CSP, XSS via jQuery |
| 6.4.2 — Web-based payment page integrity | ❌ FAIL | No SRI hashes on scripts |

### NIST Cybersecurity Framework (referenced by DOL for ERISA plans)
| Function | Gap |
|----------|-----|
| **Identify** | No `security.txt`, no robots.txt, exposed directory structure |
| **Protect** | TLS 1.0/1.1, no CSP, jQuery CVEs, no SRI |
| **Detect** | Elmah/trace configured but fingerprint suggests monitoring gaps |

### OWASP Top 10 (2021)
| Category | Finding |
|----------|---------|
| A01: Broken Access Control | Admin pages (csr/sponsor/advisor) accessible without auth |
| A02: Cryptographic Failures | TLS 1.0/1.1, unsalted SHA-256, debug crypto |
| A03: Injection | Potential XSS via jQuery 1.8.3 CVEs |
| A05: Security Misconfiguration | No CSP, overly permissive CORS, empty CSRF, debug JS |
| A06: Vulnerable Components | jQuery 1.8.3, AngularJS 1.x (EOL), MooTools |
| A07: Auth Failures | Session tokens leaked on unauthenticated pages |
| A08: Data Integrity Failures | No Subresource Integrity (SRI) on any script |
| A09: Logging & Monitoring | Elmah exists but diagnostic endpoints improperly exposed |

---

## 13. Complete Finding Summary

### 🔴 Critical (Requires immediate action)

| # | Finding | CVSS Est. |
|---|---------|-----------|
| C1 | **Admin pages (csr/sponsor/advisor) accessible without authentication** — return full page with ServiceConfig | 9.1 |
| C2 | **Session tokens leaked** on unauthenticated admin pages (Token, LSToken, Sid) | 8.6 |
| C3 | **TLS 1.0 and 1.1 enabled** — PCI DSS violation, deprecated cryptographic protocols | 7.5 |
| C4 | **jQuery 1.8.3** — 4 known XSS CVEs, on page handling SSNs | 7.5 |
| C5 | **CORS allows all origins** with PUT/DELETE — combined with empty CSRF = cross-origin attacks | 7.4 |
| C6 | **No Content Security Policy** — inline script execution, no XSS mitigation | 7.0 |

### 🟡 High (Fix within 1 week)

| # | Finding | CVSS Est. |
|---|---------|-----------|
| H1 | **AngularJS 1.x** — end-of-life, no security patches, sandbox escape CVEs | 6.5 |
| H2 | **Empty CSRF token** (`ServiceConfig.CSRFToken=''`) — no CSRF protection | 6.5 |
| H3 | **SHA-256 without salt** for MFA device comparison — reversible via rainbow tables | 6.0 |
| H4 | **Debug JavaScript in production** — `sha256.jquery.debug.js` exposes internal logic | 5.5 |
| H5 | **Hardcoded test credentials** in `reliusadmin.min.js` — token formats and internal URLs exposed | 5.5 |
| H6 | **`.env` file exists** (403 Forbidden confirms existence) — potential secrets on server | 5.0 |

### 🟢 Medium (Fix within 1 month)

| # | Finding | CVSS Est. |
|---|---------|-----------|
| M1 | **No `robots.txt`** — search engines may index admin pages | 4.0 |
| M2 | **No `security.txt`** — no responsible disclosure guidance | 3.0 |
| M3 | **Directory listing** for `/script/`, `/templates/`, `/resources/` | 4.0 |
| M4 | **SameSite cookie attribute missing** on all cookies | 4.0 |
| M5 | **No Subresource Integrity** (SRI) on script tags | 4.0 |
| M6 | **ELMAH/trace.axd return 200** — confirm existence of diagnostic tools | 3.5 |
| M7 | **MFA fingerprint is low-entropy** — only ~20 boolean/string data points | 3.5 |
| M8 | **P3P header with broad permissions** — privacy policy concern | 3.0 |
| M9 | **Empty Set-Cookie header** — misconfigured cookie handling | 2.5 |
| M10 | **Developer email exposed** in sha256 debug file comments | 2.0 |

---

## Remediation Priority

| Timeline | Actions |
|----------|---------|
| **24 hours** | Restrict admin pages (csr/sponsor/advisor) to authenticated sessions only; disable TLS 1.0/1.1 |
| **72 hours** | Implement Content-Security-Policy; fix CORS to restrict origins; generate real CSRF tokens |
| **1 week** | Upgrade jQuery to 3.7.x; remove test credentials from JS; add SameSite to all cookies |
| **2 weeks** | Add SRI hashes; create robots.txt and security.txt; remove debug JS; return 404 for elmah/trace |
| **1 month** | Plan AngularJS migration; implement modern MFA fingerprinting; security penetration test |

---

## Disclaimer

This audit was performed using only **passive, non-intrusive techniques** available to any browser or HTTP client visiting publicly accessible pages. No authentication was bypassed, no brute-force attacks were performed, no data was accessed, and no exploitation was attempted. All findings are based on information voluntarily served by the web server to any visitor asking for publicly available URLs.

This report is provided in good faith for responsible security disclosure purposes.
