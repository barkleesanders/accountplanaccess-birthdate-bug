# Security Audit & Bug Report — accountplanaccess.com

> **Responsible Disclosure:** This report documents front-end bugs and security vulnerabilities found on publicly accessible pages of the NextLevel retirement plan administration platform. No authentication was bypassed, no participant data was accessed, and no exploit was performed. This report is intended to help the vendor (Broadridge/FIS) fix the issues. The vendor has been notified via their official security disclosure channel (`Security@broadridge.com`).

## Reports

| Document | Description |
|----------|-------------|
| **[This README](#birthdate-bug-analysis)** | Birthdate validation bugs preventing credential reset |
| **[Full Security Audit](./FULL_SECURITY_AUDIT.md)** | SSL/TLS, HTTP headers, exposed admin pages, session tokens, directory exposure, JS CVEs, MFA weaknesses, cookie security, compliance gaps |
| **[OData API Exposure](./ODATA_API_EXPOSURE.md)** | Unauthenticated `$metadata` endpoint leaking full 191KB API schema including plaintext password and SSN fields across 60+ entity types |
| **[Deep Dive: SHA-256 & Architecture](./DEEP_DIVE_SHA256_AND_ARCHITECTURE.md)** | Exposed test credentials, internal API endpoints, MFA/OTP flow architecture, Schwab PCRA integration |
| **[Fixes & Recommendations](./FIXES_AND_RECOMMENDATIONS.md)** | Actionable fixes for all bugs and vulnerabilities, dependency upgrades, AI prompt for automated remediation, legal exposure analysis |

## Critical Findings Summary

| # | Severity | Finding | Report |
|---|----------|---------|--------|
| 1 | **CRITICAL** | Admin pages (csr/sponsor/advisor) return 200 with session tokens to unauthenticated visitors | [Full Audit](./FULL_SECURITY_AUDIT.md#4-exposed-pages--unauthenticated-admin-access) |
| 2 | **CRITICAL** | OData `$metadata` exposes full API schema (191KB, 60+ entities) without auth — includes `passwdTxt` and `ssNum` fields | [OData Exposure](./ODATA_API_EXPOSURE.md#2-metadata-endpoint--full-schema-exposure) |
| 3 | **CRITICAL** | Token entity schema reveals plaintext password field (`passwdTxt`) and SSN field (`ssNum`) | [OData Exposure](./ODATA_API_EXPOSURE.md#3-token-entity--plaintext-password-field) |
| 4 | **CRITICAL** | Session tokens (Token, LSToken, Sid) leaked on every unauthenticated page load | [Full Audit](./FULL_SECURITY_AUDIT.md#5-session-token-leakage) |
| 5 | **CRITICAL** | TLS 1.0 and 1.1 enabled — PCI DSS violation | [Full Audit](./FULL_SECURITY_AUDIT.md#1-ssltls-configuration) |
| 6 | **CRITICAL** | jQuery 1.8.3 with 4 known XSS CVEs on pages handling SSNs | [Full Audit](./FULL_SECURITY_AUDIT.md#7-javascript-library-inventory--cves) |
| 7 | **HIGH** | Hardcoded test credentials in `reliusadmin.min.js` including FIS employee email | [Deep Dive](./DEEP_DIVE_SHA256_AND_ARCHITECTURE.md#2-exposed-serviceconfig-test-credentials) |
| 8 | **HIGH** | Birthdate validation completely broken — prevents credential reset | [Below](#birthdate-bug-analysis) |

---

## Birthdate Bug Analysis

### Summary

The front-end source code of `https://www.accountplanaccess.com/NextLevel/default.aspx` contains **multiple bugs** in the birthdate validation pipeline on the **"Request Credentials"** (forgot password) form. The birthdate field (`BIRTHDATE1`) fails validation due to a combination of a broken datepicker configuration and a flawed `isDate()` function.

This prevents users from resetting their credentials via the self-service form.

## Where the Birthdate Field Lives

The birthdate input appears in the **"Request Credentials"** form (visible after clicking "Forgot User ID or Password?"):

```html
<input type="text" name="BIRTHDATE1" value="" maxlength="10"
       onChange="isDate(this);" id="BIRTHDATE1"
       class="form-control"
       data-date-start-date="01/01/1900"
       data-date-end-date="javascript:new Date()" />
```

---

## Bugs Found

### 🔴 Bug 1: Broken `data-date-end-date` Attribute (Primary Root Cause)

```html
data-date-end-date="javascript:new Date()"
```

This attribute is used by the Bootstrap datepicker to set the maximum selectable date. **The value `javascript:new Date()` is a string literal, not executable JavaScript.** The datepicker expects a date string like `02/25/2026` or a `Date` object, but instead receives the literal string `"javascript:new Date()"`.

**Effect:** The datepicker either:
- Fails silently and disables all dates (nothing selectable)
- Throws an internal error when parsing and blocks interaction
- Allows selection but the date comparison against the invalid end-date string causes rejection

**Fix:** Replace with a valid date string or set dynamically:
```html
<!-- Option A: Static date (not ideal, needs updating) -->
data-date-end-date="12/31/2026"
```
```javascript
// Option B: Dynamic (preferred)
jQuery('#BIRTHDATE1').datepicker({ endDate: new Date() });
```

---

### 🔴 Bug 2: `isDate()` Function Rejects Valid Dates Silently

The `isDate()` function in `javascript.js` (line ~267) is called `onChange` of the birthdate field:

```javascript
function isDate(Object, blnSuppress) {
    // ...
    if (Object.value) {
        inputStr = Object.value;
    } else {
        if (!(Object instanceof String)) {
            inputStr = Object.value; // ← Object.value is undefined/empty = inputStr is ""
        }
    }
    if (inputStr === '') {
        return false; // ← Returns false silently with no error message
    }
    // ...
}
```

If the datepicker fails to populate the field value (due to Bug 1), `Object.value` will be empty, and `isDate()` returns `false` with **no error message shown to the user** — the date just silently doesn't validate.

---

### 🟡 Bug 3: `submitForm()` Double-Validates Non-existent Field

In `forgotpassword.js`, the submit handler validates BOTH `BIRTHDATE1` **and** `BIRTHDATE` (without the `1` suffix):

```javascript
if (document.verification.BIRTHDATE1 && blnSubmit === true) {
    if (!isDate(document.verification.BIRTHDATE1) || document.verification.BIRTHDATE1.value == '') {
        showAlert(false, strBirthDateRequired, '');
        blnSubmit = false;
    }
}
// ...later...
if (document.verification.BIRTHDATE && blnSubmit === true) {
    if (!isDate(document.verification.BIRTHDATE) || document.verification.BIRTHDATE.value == '') {
        showAlert(false, strBirthDateRequired, '');
        blnSubmit = false;
    }
}
```

The form could fail even if `BIRTHDATE1` passes, because it also checks for a potentially non-existent `BIRTHDATE` field.

---

### 🟡 Bug 4: Two-Digit Year Cutoff at Year 30

In the `isDate()` function:

```javascript
if (yyyy < 100) {
    if (yyyy >= 30) {
        yyyy += 1900;  // 30-99 → 1930-1999
    } else {
        yyyy += 2000;  // 00-29 → 2000-2029
    }
}
```

Entering `12/25/25` (intending 1925) would be interpreted as **2025**, which is incorrect for a birth year. The cutoff of 30 is arbitrary and could cause confusion for older birthdates.

---

## Root Cause

**The primary root cause is Bug 1.** The `data-date-end-date="javascript:new Date()"` attribute is malformed. The datepicker can't parse the end-date, so it either blocks date selection entirely or doesn't properly initialize, leaving the field empty when the form is submitted.

---

## Security Observations

While analyzing the code and API, the following additional issues were noted. See the [Full Security Audit](./FULL_SECURITY_AUDIT.md) and [OData API Exposure](./ODATA_API_EXPOSURE.md) reports for complete details.

| Finding | Severity | Detail |
|---------|----------|--------|
| OData `$metadata` exposes full API schema without auth | **Critical** | 191KB schema reveals 60+ entity types including `passwdTxt` (plaintext password) and `ssNum` (SSN) fields — [details](./ODATA_API_EXPOSURE.md) |
| Token entity reveals plaintext password storage | **Critical** | `passwdTxt` field name strongly implies passwords stored/transmitted as plaintext — [details](./ODATA_API_EXPOSURE.md#3-token-entity--plaintext-password-field) |
| `ISOCountryCodes` returns data without auth | Medium | Confirms inconsistent authentication enforcement across OData endpoints |
| SSN field transmitted in plain text over POST | Medium | `INITIALSSN` field value is sent without client-side encryption |
| CSRF token appears static/empty | Low | `ServiceConfig.CSRFToken=''` is empty in the page source |
| Anti-clickjacking via JS (not headers) | Low | Uses `<style>body{display:none}</style>` + JS instead of `X-Frame-Options` / CSP headers |
| jQuery 1.8.3 loaded alongside MooTools 1.6 | Low | Ancient jQuery version with known XSS vulnerabilities (CVE-2015-9251, CVE-2019-11358, CVE-2020-11022) |
| SHA-256 hashing done client-side with debug JS | Info | `sha256.jquery.debug.js` — debug/unminified version in production |
| P3P header with broad permissions | Info | `CP="IDC DSP COR CURa ADMa OUR IND PHY ONL COM STA"` |

---

## Workaround

If you encounter this bug:

1. **Manually type** your birthdate in `MM/DD/YYYY` format (e.g., `01/15/1990`) instead of using the datepicker calendar
2. If that doesn't work, try a **different browser** (Chrome, Firefox, Safari, Edge)
3. Contact customer support — the phone numbers are typically available through your plan administrator

---

## Vendor Disclosure

- **Vendor:** Broadridge Financial Solutions / FIS (Fidelity National Information Services)
- **Platform:** NextLevel (Relius Admin Web) — retirement plan administration
- **Disclosure channel:** `Security@broadridge.com` (per [Broadridge Security Capabilities page](https://www.broadridge.com/about/security-capabilities))
- **HackerOne:** [hackerone.com/broadridge](https://hackerone.com/broadridge) (Vulnerability Disclosure Policy)
- **Date discovered:** February 25, 2026
- **Status:** Reported
- **SSL Certificate Org:** Fidelity National Information Services (FIS)

---

## License

This report is provided for informational and security research purposes under responsible disclosure principles. No proprietary source code is included — only publicly visible client-side JavaScript from the login page is referenced.
