# Security Audit & Bug Report — accountplanaccess.com

> **Responsible Disclosure:** This report documents front-end bugs and security vulnerabilities found on publicly accessible pages of the NextLevel retirement plan administration platform (Relius Admin Web). No authentication was bypassed, no participant data was accessed, and no exploit was performed. This report is intended to help the vendor (Broadridge/FIS) fix the issues.

> **Vendor:** Broadridge Financial Solutions / FIS (Fidelity National Information Services)
> **Platform:** NextLevel (Relius Admin Web) — retirement plan administration
> **Disclosure channel:** `Security@broadridge.com` | [HackerOne](https://hackerone.com/broadridge)
> **Date discovered:** February 25, 2026
> **Status:** Reported

---

## Executive Summary

The NextLevel platform at `accountplanaccess.com` — a retirement plan administration system handling 401(k) accounts, Social Security Numbers, and financial data — has **critical security vulnerabilities** across its publicly accessible attack surface.

The most severe finding is that the **OData `$metadata` endpoint returns the entire 191KB API schema without authentication**, exposing 60+ entity types including a `Token` entity with fields named `passwdTxt` (plaintext password) and `ssNum` (Social Security Number). Additionally, admin portals (CSR, Sponsor, Advisor) serve full page HTML with session tokens to unauthenticated visitors, TLS 1.0/1.1 are enabled in violation of PCI DSS, and the platform runs jQuery 1.8.3 with 4 known XSS CVEs on pages that collect SSNs.

A broken datepicker configuration also prevents users from resetting their credentials via the self-service form.

---

## Detailed Reports

| Document | Description |
|----------|-------------|
| **[OData API Exposure](./ODATA_API_EXPOSURE.md)** | Unauthenticated `$metadata` endpoint leaks full 191KB API schema — 60+ entity types including plaintext password and SSN fields, financial balances, PII structure, and complete transaction model |
| **[Full Security Audit](./FULL_SECURITY_AUDIT.md)** | SSL/TLS configuration, HTTP headers, exposed admin pages, session token leakage, directory exposure, JavaScript CVE inventory, MFA weaknesses, cookie security, compliance gap analysis |
| **[Deep Dive: SHA-256 & Architecture](./DEEP_DIVE_SHA256_AND_ARCHITECTURE.md)** | Exposed test credentials in production JS, internal API endpoints, full MFA/OTP flow architecture, Charles Schwab PCRA integration details |
| **[Fixes & Recommendations](./FIXES_AND_RECOMMENDATIONS.md)** | Actionable code fixes for all bugs and vulnerabilities, dependency upgrade path, AI prompt for automated remediation, ERISA/SEC legal exposure analysis |

---

## All Findings

### Critical

| # | Finding | CVSS | Report |
|---|---------|------|--------|
| C1 | **Admin pages (csr/sponsor/advisor) return 200 with session tokens** to unauthenticated visitors | 9.1 | [Full Audit §4](./FULL_SECURITY_AUDIT.md#4-exposed-pages--unauthenticated-admin-access) |
| C2 | **Session tokens leaked** (Token, LSToken, Sid) on every unauthenticated page load | 8.6 | [Full Audit §5](./FULL_SECURITY_AUDIT.md#5-session-token-leakage) |
| C3 | **Token entity exposes `passwdTxt` (plaintext password) and `ssNum` (SSN)** in OData schema | 8.2 | [OData §3](./ODATA_API_EXPOSURE.md#3-token-entity--plaintext-password-field) |
| C4 | **OData `$metadata` returns full 191KB API schema** without authentication — 60+ entity types | 7.5 | [OData §2](./ODATA_API_EXPOSURE.md#2-metadata-endpoint--full-schema-exposure) |
| C5 | **TLS 1.0 and 1.1 enabled** — PCI DSS violation, deprecated protocols | 7.5 | [Full Audit §1](./FULL_SECURITY_AUDIT.md#1-ssltls-configuration) |
| C6 | **jQuery 1.8.3** — 4 known XSS CVEs on pages handling SSNs | 7.5 | [Full Audit §7](./FULL_SECURITY_AUDIT.md#7-javascript-library-inventory--cves) |
| C7 | **CORS allows all origins** with PUT/DELETE + empty CSRF token | 7.4 | [Full Audit §2](./FULL_SECURITY_AUDIT.md#2-http-security-headers) |
| C8 | **No Content Security Policy** — inline scripts, no XSS mitigation | 7.0 | [Full Audit §2](./FULL_SECURITY_AUDIT.md#2-http-security-headers) |

### High

| # | Finding | CVSS | Report |
|---|---------|------|--------|
| H1 | **Hardcoded test credentials** in `reliusadmin.min.js` — tokens, FIS employee email, internal API URLs | 5.5 | [Deep Dive §2](./DEEP_DIVE_SHA256_AND_ARCHITECTURE.md#2-exposed-serviceconfig-test-credentials) |
| H2 | **AngularJS 1.x** — end-of-life since Dec 2021, no security patches | 6.5 | [Full Audit §7](./FULL_SECURITY_AUDIT.md#7-javascript-library-inventory--cves) |
| H3 | **Empty CSRF token** — `ServiceConfig.CSRFToken=''` on all pages | 6.5 | [Full Audit §13](./FULL_SECURITY_AUDIT.md#13-complete-finding-summary) |
| H4 | **SHA-256 without salt** for MFA device comparison — reversible via rainbow tables | 6.0 | [Deep Dive §1](./DEEP_DIVE_SHA256_AND_ARCHITECTURE.md#1-the-sha-256-library) |
| H5 | **Birthdate validation broken** — prevents credential reset for all users | — | [Below](#birthdate-bug-analysis) |

### Medium

| # | Finding | CVSS | Report |
|---|---------|------|--------|
| M1 | `ISOCountryCodes` endpoint returns data without authentication | 5.0 | [OData §6](./ODATA_API_EXPOSURE.md#6-unauthenticated-data-endpoints) |
| M2 | Pre-auth tokens consume server resources on every anonymous request | 5.3 | [OData §7](./ODATA_API_EXPOSURE.md#7-pre-auth-token-analysis) |
| M3 | SSN field (`INITIALSSN`) transmitted without client-side encryption | 4.5 | [Fixes §Fix 7](./FIXES_AND_RECOMMENDATIONS.md#fix-7-ssn-transmission) |
| M4 | Directory listing enabled for `/script/`, `/templates/`, `/resources/` | 4.0 | [Full Audit §6](./FULL_SECURITY_AUDIT.md#6-directory--file-exposure) |
| M5 | SameSite cookie attribute missing on all cookies | 4.0 | [Full Audit §9](./FULL_SECURITY_AUDIT.md#9-cookie-security) |
| M6 | MFA fingerprint is low-entropy (~20 data points) | 3.5 | [Full Audit §8](./FULL_SECURITY_AUDIT.md#8-mfa-browser-fingerprinting-weakness) |
| M7 | Debug JavaScript (`sha256.jquery.debug.js`) in production | 3.5 | [Deep Dive §1](./DEEP_DIVE_SHA256_AND_ARCHITECTURE.md#1-the-sha-256-library) |

---

## Recommended Fixes

> Full code samples and implementation details: **[FIXES_AND_RECOMMENDATIONS.md](./FIXES_AND_RECOMMENDATIONS.md)**

### Immediate (24 hours)

| Fix | Finding | Action |
|-----|---------|--------|
| **A1** | C4 — `$metadata` exposed | Restrict `$metadata` to authenticated users via `web.config` `<authorization>` block or OData middleware filter |
| **A2** | C3 — `passwdTxt` field | Rename to `passwdDigest`; migrate from unsalted SHA-256 to bcrypt/Argon2 server-side |
| — | C1 — Admin pages exposed | Return 401/403 for `/csr.aspx`, `/sponsor.aspx`, `/advisor.aspx` without valid session |
| — | C5 — TLS 1.0/1.1 | Disable TLS 1.0 and 1.1 at the IIS/Akamai level |

### 1 Week

| Fix | Finding | Action |
|-----|---------|--------|
| **A3** | M1 — Unauth data endpoint | Add global `[Authorize]` filter to all OData controllers |
| — | C6 — jQuery 1.8.3 | Upgrade to jQuery 3.7.x; audit deprecated API usage |
| — | C7 — CORS + CSRF | Restrict CORS origins; generate real per-session CSRF tokens |
| — | C8 — No CSP | Add `Content-Security-Policy` and `Referrer-Policy` headers |
| — | H1 — Test credentials | Strip hardcoded `userInfo` fallback from `reliusadmin.min.js` |

### 2 Weeks

| Fix | Finding | Action |
|-----|---------|--------|
| **A4** | M2 — Token flooding | Rate-limit anonymous requests via IIS Dynamic IP Restrictions |
| **A5** | C4 — OData queries | Add `$select`/`$filter`/`$expand` restrictions on sensitive controllers |
| — | H5 — Birthdate bug | Fix `data-date-end-date` attribute; fix `isDate()` silent failure |
| — | M4 — Directory listing | Disable directory browsing in IIS |
| — | M7 — Debug JS | Replace with minified production build |

### 1 Month+

| Fix | Finding | Action |
|-----|---------|--------|
| — | H2 — AngularJS EOL | Plan migration to supported framework |
| — | H4 — Unsalted SHA-256 | Move MFA device comparison server-side with HMAC |
| — | M6 — MFA fingerprint | Implement Canvas/WebGL/AudioContext fingerprinting |

---

## Birthdate Bug Analysis

### Summary

The front-end source code of `https://www.accountplanaccess.com/NextLevel/default.aspx` contains **multiple bugs** in the birthdate validation pipeline on the **"Request Credentials"** (forgot password) form. The birthdate field (`BIRTHDATE1`) fails validation due to a broken datepicker configuration and a flawed `isDate()` function.

This **prevents users from resetting their credentials** via the self-service form.

### Where the Birthdate Field Lives

The birthdate input appears in the **"Request Credentials"** form (visible after clicking "Forgot User ID or Password?"):

```html
<input type="text" name="BIRTHDATE1" value="" maxlength="10"
       onChange="isDate(this);" id="BIRTHDATE1"
       class="form-control"
       data-date-start-date="01/01/1900"
       data-date-end-date="javascript:new Date()" />
```

### Bug 1: Broken `data-date-end-date` Attribute (Primary Root Cause)

```html
data-date-end-date="javascript:new Date()"
```

The value `javascript:new Date()` is a **string literal, not executable JavaScript**. The Bootstrap datepicker expects a date string like `02/25/2026` or a `Date` object. The datepicker either fails silently, throws an internal error, or rejects all date selections.

**Fix:**
```javascript
jQuery('#BIRTHDATE1').datepicker({ endDate: new Date() });
```

### Bug 2: `isDate()` Function Rejects Valid Dates Silently

When the datepicker fails to populate the field (due to Bug 1), `Object.value` is empty and `isDate()` returns `false` with **no error message** — the date silently doesn't validate.

```javascript
if (inputStr === '') {
    return false; // ← Silent failure, no user feedback
}
```

**Fix:** Show a user-facing error instead of returning false silently.

### Bug 3: Double Validation of BIRTHDATE/BIRTHDATE1

`forgotpassword.js` validates both `BIRTHDATE1` **and** `BIRTHDATE` (without the `1` suffix). The form fails even if `BIRTHDATE1` passes because it also checks a potentially non-existent `BIRTHDATE` field.

**Fix:** Consolidate: `var field = document.verification.BIRTHDATE1 || document.verification.BIRTHDATE;`

### Bug 4: Two-Digit Year Cutoff at Year 30

Entering `12/25/25` (intending 1925) is interpreted as **2025** due to a hardcoded cutoff of 30. For a birthdate field on a retirement platform, this is incorrect.

**Fix:** Reject two-digit years entirely for birthdate fields, or use a dynamic cutoff.

### Root Cause

**The primary root cause is Bug 1.** The malformed `data-date-end-date="javascript:new Date()"` attribute prevents the datepicker from initializing, leaving the field empty when the form is submitted.

### Workaround

If you encounter this bug:
1. **Manually type** your birthdate in `MM/DD/YYYY` format (e.g., `01/15/1990`) instead of using the datepicker calendar
2. If that doesn't work, try a **different browser** (Chrome, Firefox, Safari, Edge)
3. Contact customer support — the phone numbers are typically available through your plan administrator

---

## OData API Exposure (New Finding)

> Full analysis: **[ODATA_API_EXPOSURE.md](./ODATA_API_EXPOSURE.md)**

The OData v4 REST API at `/nextlevelapi` exposes its **complete schema** to unauthenticated visitors:

```bash
curl -s "https://www.accountplanaccess.com/nextlevelapi/\$metadata"
# → 191KB XML — full Entity Data Model, no auth required
```

### Token Entity — Plaintext Password & SSN Fields

```xml
<EntityType Name="Token">
  <Property Name="ssNum" Type="Edm.String" />          <!-- Social Security Number -->
  <Property Name="passwdTxt" Type="Edm.String" />      <!-- PLAINTEXT PASSWORD -->
  <Property Name="userNam" Type="Edm.String" />         <!-- Username (primary key) -->
  <Property Name="tokenString" Type="Edm.String" />     <!-- Auth token -->
  <Property Name="adminId" Type="Edm.Int32" />          <!-- Admin ID -->
</EntityType>
```

### PersonalData Entity — Full PII Structure

The schema reveals that the system stores: full legal name, date of birth, hire date, full mailing address (including foreign), three phone numbers with country codes, marital status, and sex — all keyed by `planId` and `pid` (participant ID).

### 60+ Entity Types Exposed

The metadata reveals the complete data model including:
- **Authentication:** Token (SSN, password, username, admin ID)
- **Personal:** PersonalData, ParticipantStatus, GeneralParticipantFile
- **Financial:** Distributions (Roth/non-Roth balances), ContributionRates, LoanModels, Transfers, Rebalances, MyPortfolioData
- **Transactions:** 12 TransRequest* entity types covering elections, loans, withdrawals, terminations, transfers
- **Integrations:** SchwabSDBData (Charles Schwab brokerage), FundFactSheets, InvestProductDetails
- **Admin:** WWWTrackingLogs (user activity), Documents, WebBinFiles, PlanStats

### Unauthenticated Data Access

The `ISOCountryCodes` endpoint returns data without any authentication:

```bash
curl -s "https://www.accountplanaccess.com/nextlevelapi/ISOCountryCodes"
# → 248 country records returned, no auth required
```

### Pre-Auth Token Format

Tokens embedded in the login page are hex-encoded AES ciphertext that **rotate per request**:

```
Hex:     4661456C4555314668325673535743535731665473413D3D...
Decoded: FaElEU1Fh2VsSWCSW1fTsA==uEqcPPfkDQnWUZ0d33SsD53gP2ooomPe/lGtmsZaW0gA
Format:  <base64-IV>==<base64-ciphertext>
```

The `ServiceSiteId` (`f77b9ff7-1c84-4e14-ac51-ae67bb908b58`) is static across all requests.

---

## Compliance Impact

| Standard | Violation |
|----------|-----------|
| **PCI DSS 4.0** | TLS 1.0/1.1 enabled (Req 2.2.7); no CSP (Req 6.4.1); jQuery CVEs (Req 6.2.4) |
| **ERISA** | Known bug prevents participants from accessing retirement accounts — potential fiduciary duty breach |
| **SEC Reg S-P** | Known XSS CVEs on pages collecting SSNs — failure to implement reasonable safeguards |
| **OWASP Top 10** | A01 Broken Access Control, A02 Cryptographic Failures, A05 Misconfiguration, A06 Vulnerable Components, A07 Auth Failures |
| **WCAG 2.1** | Silent validation failure violates Success Criterion 3.3.1 (Error Identification) |

---

## License

This report is provided for informational and security research purposes under responsible disclosure principles. No proprietary source code is included — only publicly visible client-side JavaScript and HTTP responses from publicly accessible endpoints are referenced.
