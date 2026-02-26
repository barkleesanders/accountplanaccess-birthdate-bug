# Recommended Fixes & Upgrades — accountplanaccess.com NextLevel

> This document provides actionable fixes for all bugs identified in the [bug report](./README.md), along with upgrade recommendations and a ready-to-use AI prompt for automated remediation.

---

## Table of Contents

1. [Critical Bug Fixes](#critical-bug-fixes)
2. [API & OData Fixes](#api--odata-fixes)
3. [Security Fixes](#security-fixes)
4. [Dependency Upgrades](#dependency-upgrades)
5. [Claude Code Prompt for Automated Fix](#claude-code-prompt-for-automated-fix)
6. [Impact Assessment & Legal Exposure](#impact-assessment--legal-exposure)

---

## Critical Bug Fixes

### Fix 1: Broken `data-date-end-date` Attribute

**File:** Server-side template that generates `default.aspx` / `forgotpassword.aspx`

**Current (broken):**
```html
<input type="text" name="BIRTHDATE1" value="" maxlength="10"
       onChange="isDate(this);" id="BIRTHDATE1"
       class="form-control"
       data-date-start-date="01/01/1900"
       data-date-end-date="javascript:new Date()" />
```

**Fixed (Option A — server-side date string):**
```html
<input type="text" name="BIRTHDATE1" value="" maxlength="10"
       onChange="isDate(this);" id="BIRTHDATE1"
       class="form-control"
       data-date-start-date="01/01/1900"
       data-date-end-date="<%= DateTime.Now.ToString("MM/dd/yyyy") %>" />
```

**Fixed (Option B — JavaScript initialization, preferred):**
```html
<input type="text" name="BIRTHDATE1" value="" maxlength="10"
       onChange="isDate(this);" id="BIRTHDATE1"
       class="form-control"
       data-date-start-date="01/01/1900" />
```
```javascript
// Add to document.ready or after DOM load
jQuery(document).ready(function() {
    jQuery('#BIRTHDATE1').datepicker({
        format: 'mm/dd/yyyy',
        startDate: '01/01/1900',
        endDate: new Date(),       // ← Dynamic, always today
        autoclose: true,
        todayHighlight: true
    });
});
```

---

### Fix 2: Silent Validation Failure in `isDate()`

**File:** `script/javascript.js` (~line 267)

**Current (broken):**
```javascript
function isDate(Object, blnSuppress) {
    var blnSuppressOutput = false;
    var inputStr = '';
    // ...
    if (Object.value) {
        inputStr = Object.value;
    } else {
        if (!(Object instanceof String)) {
            inputStr = Object.value; // ← Always empty when value is falsy
        } else {
            blnSuppressOutput = true;
            inputStr = Object;
        }
    }
    if (inputStr === '') {
        return false; // ← Silent failure, no user feedback
    }
    // ...
}
```

**Fixed:**
```javascript
function isDate(dateObj, blnSuppress) {
    var blnSuppressOutput = blnSuppress || false;
    var inputStr = '';

    // Handle both DOM elements and string values
    if (dateObj && typeof dateObj === 'object' && 'value' in dateObj) {
        inputStr = dateObj.value || '';
    } else if (typeof dateObj === 'string') {
        inputStr = dateObj;
        blnSuppressOutput = true;
    }

    // Trim whitespace
    inputStr = inputStr.trim();

    if (inputStr === '') {
        if (!blnSuppressOutput) {
            showAlert(false, 'Please enter a date in mm/dd/yyyy format.', '');
            try { dateObj.focus(); } catch(e) {}
        }
        return false;
    }

    // ... rest of validation unchanged ...
}
```

**Key changes:**
- Renamed parameter from `Object` (reserved word) to `dateObj`
- Added `.trim()` to handle whitespace
- Shows user-facing error instead of silent failure
- Cleaner type checking

---

### Fix 3: Double Validation of BIRTHDATE/BIRTHDATE1

**File:** `script/forgotpassword.js` (~line 85-103)

**Current (redundant):**
```javascript
// Validates BIRTHDATE1
if (document.verification.BIRTHDATE1 && blnSubmit === true) {
    if (!isDate(document.verification.BIRTHDATE1) || document.verification.BIRTHDATE1.value == '') {
        showAlert(false, strBirthDateRequired, '');
        blnSubmit = false;
    }
}
// ...
// ALSO validates BIRTHDATE (may not exist in DOM)
if (document.verification.BIRTHDATE && blnSubmit === true) {
    if (!isDate(document.verification.BIRTHDATE) || document.verification.BIRTHDATE.value == '') {
        showAlert(false, strBirthDateRequired, '');
        blnSubmit = false;
    }
}
```

**Fixed:**
```javascript
// Validate whichever birthdate field exists (BIRTHDATE1 takes priority)
var birthdateField = document.verification.BIRTHDATE1 || document.verification.BIRTHDATE;
if (birthdateField && blnSubmit === true) {
    if (!isDate(birthdateField) || birthdateField.value.trim() === '') {
        showAlert(false, strBirthDateRequired, '');
        blnSubmit = false;
    }
}
```

---

### Fix 4: Two-Digit Year Cutoff

**File:** `script/javascript.js` (~line 357)

**Current:**
```javascript
if (yyyy < 100) {
    if (yyyy >= 30) {
        yyyy += 1900;  // 30 → 1930
    } else {
        yyyy += 2000;  // 29 → 2029
    }
}
```

**Fixed (dynamic cutoff based on current year):**
```javascript
if (yyyy < 100) {
    var currentYear = new Date().getFullYear();
    var cutoff = currentYear - 2000 + 10; // e.g., in 2026 → cutoff = 36
    if (yyyy > cutoff) {
        yyyy += 1900;
    } else {
        yyyy += 2000;
    }
}
```

**Or better — reject two-digit years entirely for birthdate fields:**
```javascript
if (yyyy < 100) {
    if (!blnSuppressOutput) {
        showAlert(false, 'Please enter a 4-digit year (e.g., 1985).', '');
    }
    return false;
}
```

---

## API & OData Fixes

### Fix A1: Restrict $metadata Endpoint (CRITICAL)

The OData `$metadata` endpoint returns the full 191KB API schema without authentication, exposing all 60+ entity types including field names like `passwdTxt` (plaintext password) and `ssNum` (SSN).

**Option A — web.config restriction:**
```xml
<location path="nextlevelapi/$metadata">
  <system.web>
    <authorization>
      <deny users="?" />
    </authorization>
  </system.web>
</location>
```

**Option B — OData middleware filter:**
```csharp
// Custom DelegatingHandler to block unauthenticated $metadata access
public class MetadataAuthHandler : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri.AbsolutePath.Contains("$metadata") &&
            !request.GetRequestContext().Principal.Identity.IsAuthenticated)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized));
        }
        return base.SendAsync(request, cancellationToken);
    }
}
```

---

### Fix A2: Rename `passwdTxt` and Implement Proper Password Hashing (CRITICAL)

The Token entity field name `passwdTxt` implies plaintext password storage/transmission. Even if the client hashes with SHA-256, unsalted SHA-256 is inadequate.

**Step 1 — Rename the field:**
```csharp
// Before
public string passwdTxt { get; set; }

// After
public string passwdDigest { get; set; }
```

**Step 2 — Implement bcrypt server-side:**
```csharp
// NuGet: Install-Package BCrypt.Net-Next
using BCrypt.Net;

// Registration: hash the client-submitted SHA-256 with bcrypt
string bcryptHash = BCrypt.HashPassword(clientSha256Hash, workFactor: 12);

// Login: verify against stored bcrypt hash
bool valid = BCrypt.Verify(clientSha256Hash, storedBcryptHash);
```

**Step 3 — Migration plan:**
1. Add `passwdDigest` column alongside `passwdTxt`
2. On next login, verify against `passwdTxt` (SHA-256), then bcrypt-hash and store in `passwdDigest`
3. Once all active users have migrated, remove `passwdTxt` column

---

### Fix A3: Require Authentication on All OData Endpoints (HIGH)

The `ISOCountryCodes` endpoint returns data without authentication. Apply a global authorization filter:

```csharp
// Global OData authorization
public static class WebApiConfig
{
    public static void Register(HttpConfiguration config)
    {
        // Apply [Authorize] globally to all OData controllers
        config.Filters.Add(new AuthorizeAttribute());
    }
}
```

---

### Fix A4: Rate-Limit Pre-Auth Token Generation (MEDIUM)

Every anonymous request to `/NextLevel/` generates server-side cryptographic tokens, consuming resources. Implement rate limiting:

```xml
<!-- IIS Dynamic IP Restrictions in web.config -->
<system.webServer>
  <security>
    <dynamicIpSecurity>
      <denyByConcurrentRequests enabled="true" maxConcurrentRequests="10" />
      <denyByRequestRate enabled="true" maxRequests="30"
                         requestIntervalInMilliseconds="5000" />
    </dynamicIpSecurity>
  </security>
</system.webServer>
```

---

### Fix A5: Add OData Query Restrictions (MEDIUM)

Prevent excessive data extraction by limiting OData query capabilities:

```csharp
// On sensitive controllers
[Page(MaxTop = 50)]
[Count(Disabled = true)]
[Select(SelectType = SelectExpandType.Allowed)]
[Filter(Disabled = true)] // or whitelist specific filterable properties
public class PersonalDatasController : ODataController { }
```

---

## Security Fixes

### Fix 5: Empty CSRF Token

**Current:**
```javascript
ServiceConfig.CSRFToken = '';
```

**Fix:** The server must generate a unique CSRF token per session and inject it:
```javascript
ServiceConfig.CSRFToken = '<%= Session["CSRFToken"] %>';
```

All form submissions should include and validate this token server-side.

---

### Fix 6: Anti-Clickjacking via JavaScript → HTTP Headers

**Current (JavaScript-based, bypassable):**
```html
<style id="antiClickjack">body{display:none !important;}</style>
<script>
if (self === top) {
    var antiClickjack = document.getElementById("antiClickjack");
    antiClickjack.parentNode.removeChild(antiClickjack);
} else {
    top.location = self.location;
}
</script>
```

**Fix:** Add proper HTTP response headers (server-side, e.g., in `web.config`):
```xml
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <add name="X-Frame-Options" value="DENY" />
      <add name="Content-Security-Policy" value="frame-ancestors 'none'" />
      <add name="X-Content-Type-Options" value="nosniff" />
      <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
      <add name="Permissions-Policy" value="geolocation=(), camera=(), microphone=()" />
    </customHeaders>
  </httpProtocol>
</system.webServer>
```

The JavaScript-based approach should be kept as a fallback but is not sufficient alone.

---

### Fix 7: SSN Transmission

**Current:** SSN is sent as plain form POST data in `INITIALSSN`.

**Fix:** Hash the SSN client-side before transmission (you already have `sha256.jquery.debug.js` loaded):
```javascript
// Before form submit
var ssnField = document.getElementById('SSN');
var hashedSSN = jQuery.sha256(ssnField.value);
document.verification.INITIALSSN.value = hashedSSN;
```

**Better:** Use TLS (already in place via HTTPS) and ensure the server validates against stored hashes. Remove the debug SHA-256 library and use a production build.

---

### Fix 8: Remove Debug JavaScript from Production

**Current:**
```html
<script type="text/javascript" src="script/sha256.jquery.debug.js"></script>
```

**Fix:**
```html
<script type="text/javascript" src="script/sha256.jquery.min.js"></script>
```

Debug files expose internal logic, are larger, and may contain verbose error messages that aid attackers.

---

## Dependency Upgrades

| Current | Version | Recommended | Why |
|---------|---------|-------------|-----|
| jQuery | 1.8.3 | 3.7.x | CVE-2015-9251, CVE-2019-11358, CVE-2020-11022, CVE-2020-11023 — XSS vulnerabilities |
| MooTools | 1.6.0 | Remove or 1.6.0+ | Conflicts with jQuery; prototype pollution risks |
| Bootstrap Datepicker | Unknown | Latest | Fix `data-date-end-date` parsing |
| DD_roundies | 0.0.2a | Remove | IE6/7/8 rounded corners polyfill — obsolete |
| DHTML Window Widget | Unknown | Remove | Legacy Dynamic Drive widget — security risk |
| Angular (ng-model refs) | 1.x | Remove or upgrade to 16+ | AngularJS 1.x is end-of-life since Dec 2021 |

### Upgrade Priority:
1. 🔴 **jQuery 1.8.3 → 3.7.x** (known exploitable XSS CVEs)
2. 🔴 **AngularJS 1.x → modern framework or remove** (EOL, no security patches)
3. 🟡 **Remove MooTools** (conflicts, prototype pollution)
4. 🟡 **Remove DD_roundies, DHTML Window** (dead libraries)

---

## Claude Code Prompt for Automated Fix

The following prompt can be given to **Claude Code** (or any AI coding assistant) by Broadridge's development team to automatically find and fix all identified issues:

````
/requirements-start NextLevel Login Page Security & Bug Remediation

## Context
We have a legacy ASP.NET WebForms application called "NextLevel" served at accountplanaccess.com. 
The login page (default.aspx) and forgot password page (forgotpassword.aspx) have critical bugs 
preventing users from resetting their credentials, along with several security vulnerabilities.

## Task 1: Fix Broken Datepicker (CRITICAL)
Find all instances of `data-date-end-date="javascript:new Date()"` across all .aspx, .ascx, 
.master, and .html files. Replace with server-side rendered date string using 
`<%= DateTime.Now.ToString("MM/dd/yyyy") %>` or initialize via jQuery datepicker in JavaScript 
with `endDate: new Date()`. Verify the Bootstrap datepicker version in use and ensure 
compatibility with the fix.

## Task 2: Fix isDate() Validation (CRITICAL)
In script/javascript.js, find the `isDate()` function (~line 267). Apply these fixes:
- Rename parameter from `Object` to `dateObj` (Object is a reserved word)
- Fix the empty value fallthrough: when `dateObj.value` is falsy, show a user-facing error 
  instead of returning false silently
- Add `.trim()` to inputStr before validation
- Fix the two-digit year cutoff: either make it dynamic based on current year, or reject 
  2-digit years entirely for birthdate fields

## Task 3: Fix Double Validation in forgotpassword.js (MEDIUM)
In script/forgotpassword.js, the `submitForm()` function validates both `BIRTHDATE1` AND 
`BIRTHDATE`. Consolidate to check whichever field exists with fallback:
`var birthdateField = document.verification.BIRTHDATE1 || document.verification.BIRTHDATE;`

## Task 4: Security Headers (MEDIUM)
In web.config, add these HTTP response headers:
- X-Frame-Options: DENY
- Content-Security-Policy: frame-ancestors 'none'
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
Keep the existing JavaScript anti-clickjacking as a fallback.

## Task 5: CSRF Token (MEDIUM)
Find where `ServiceConfig.CSRFToken=''` is set (in the page head). Ensure the server generates 
a unique token per session and injects it. Verify all form submissions include and validate 
this token server-side.

## Task 6: Upgrade jQuery (HIGH)
Replace jQuery 1.8.3 (`script/jquery_1.8.3-min.js`) with jQuery 3.7.x. Run `jQuery.noConflict()` 
is already called — verify MooTools compatibility. Search for deprecated jQuery APIs that changed 
between 1.8 and 3.7 (e.g., `.live()`, `.die()`, `.size()`, `$.browser`, `.andSelf()`, 
deferred `.pipe()`, `.on("ready")`, etc.) and update all call sites.

## Task 7: Remove Debug Files (LOW)
Replace `script/sha256.jquery.debug.js` with the minified production version. Search for any 
other `.debug.js` or unminified vendor files in the script/ directory.

## Task 8: Remove Dead Libraries (LOW)
Evaluate and remove if unused:
- DD_roundies_0.0.2a.js (IE6-8 polyfill)
- DHTML Window Widget (windowfiles/dhtmlwindow.js)
- Any other IE-specific shims beyond html5shiv.js

## Testing
After all changes:
1. Test the forgot password flow end-to-end: click "Forgot User ID or Password?", 
   enter test SSN/birthdate/zip, verify form submits successfully
2. Test datepicker opens, allows date selection, and populates the field
3. Test manual date entry in MM/DD/YYYY format validates correctly
4. Test two-digit year entry is handled correctly or rejected
5. Verify no JavaScript console errors on page load
6. Run OWASP ZAP or similar against the login page to verify security headers
````

---

## Impact Assessment & Legal Exposure

### User Impact

| Impact | Severity | Description |
|--------|----------|-------------|
| **Account lockout** | 🔴 Critical | Users cannot reset passwords via self-service, forcing them to call support. For retirement accounts, this can delay time-sensitive financial decisions. |
| **Support cost** | 🟡 High | Every user blocked by this bug generates a support call. At scale, this represents significant operational cost. |
| **User abandonment** | 🟡 High | Users who can't access their retirement accounts may lose trust in the platform and seek to move their assets. |
| **Accessibility** | 🟡 Medium | The silent validation failure violates WCAG 2.1 Success Criterion 3.3.1 (Error Identification) — errors must be described to the user in text. |

### Security Impact

| Impact | Severity | Description |
|--------|----------|-------------|
| **XSS via jQuery 1.8.3** | 🔴 Critical | CVE-2020-11022 and CVE-2020-11023 allow cross-site scripting through jQuery's HTML parsing. On a page that handles SSNs and financial data, this is a serious attack vector. |
| **Clickjacking** | 🟡 Medium | JavaScript-only frame-busting can be bypassed (e.g., via `sandbox` attribute on iframes). An attacker could overlay the login form to steal credentials. |
| **CSRF** | 🟡 Medium | Empty CSRF token means the forgot-password form could be submitted by a malicious third-party site on behalf of a victim. |

### Legal & Regulatory Exposure

#### 1. ERISA (Employee Retirement Income Security Act)
NextLevel is a **retirement plan administration platform**. Under ERISA:
- Plan fiduciaries have a duty to act prudently and in the best interest of plan participants
- A known bug that **prevents participants from accessing their retirement accounts** could constitute a breach of fiduciary duty
- The DOL (Department of Labor) has issued [guidance on cybersecurity best practices](https://www.dol.gov/agencies/ebsa/key-topics/retirement-benefits/cybersecurity) for ERISA-covered plans, including keeping software up to date and patching known vulnerabilities

#### 2. SEC Regulation S-P (Privacy of Consumer Financial Information)
- Requires financial institutions to have written policies to protect customer information
- Running jQuery 1.8.3 with **known XSS CVEs** on a page that collects Social Security Numbers could be viewed as a failure to implement reasonable safeguards
- The SEC has [brought enforcement actions](https://www.sec.gov/spotlight/cybersecurity-enforcement-actions) for inadequate cybersecurity controls

#### 3. State Data Breach Notification Laws
- If the jQuery XSS vulnerabilities were exploited to steal SSNs, all 50 states have data breach notification laws requiring disclosure
- New York's SHIELD Act and California's CCPA impose additional requirements
- **Average cost of a data breach involving financial records: $5.97M** (IBM Cost of a Data Breach Report 2024)

#### 4. WCAG / ADA Compliance
- Silent validation failures (Bug 2) violate WCAG 2.1 Level A, Success Criterion 3.3.1
- Financial services websites face increasing ADA litigation — [over 4,000 digital accessibility lawsuits were filed in 2023](https://www.adatitleiii.com/2024/01/federal-website-accessibility-lawsuits-increased-in-2023/)

#### 5. Negligence / Duty of Care
- A known, documented, publicly disclosed bug that prevents account access creates a **duty to remediate**
- The longer the gap between disclosure and fix, the greater the legal exposure
- This public disclosure creates a timestamp that could be referenced in any future litigation

### Timeline Recommendation

| Priority | Fix | Deadline |
|----------|-----|----------|
| 🔴 P0 | Restrict `$metadata` endpoint to authenticated users (Fix A1) | **24 hours** |
| 🔴 P0 | Fix `data-date-end-date` attribute (Bug 1) | **24 hours** |
| 🔴 P0 | Rename `passwdTxt` field; implement bcrypt (Fix A2) | **1 week** |
| 🔴 P0 | Upgrade jQuery 1.8.3 → 3.7.x | **1 week** |
| 🟡 P1 | Require auth on all OData endpoints including ISOCountryCodes (Fix A3) | **1 week** |
| 🟡 P1 | Fix `isDate()` silent failure (Bug 2) | **1 week** |
| 🟡 P1 | Add security headers (X-Frame-Options, CSP) | **1 week** |
| 🟡 P1 | Fix CSRF token generation | **1 week** |
| 🟢 P2 | Rate-limit pre-auth token generation (Fix A4) | **2 weeks** |
| 🟢 P2 | Add OData query restrictions (Fix A5) | **2 weeks** |
| 🟢 P2 | Fix double validation (Bug 3) | **2 weeks** |
| 🟢 P2 | Fix year cutoff (Bug 4) | **2 weeks** |
| 🟢 P2 | Remove debug JS, dead libraries | **2 weeks** |
| 🔵 P3 | AngularJS migration plan | **Quarter** |

---

## Disclaimer

This report is provided in good faith for security research purposes under responsible disclosure principles. The author is not affiliated with Broadridge Financial Solutions. All analysis was performed on publicly accessible client-side code served to any visitor of the login page. No authentication was bypassed, no proprietary server-side code was accessed, and no user data was exposed or obtained.
