# Deep Dive: `sha256.jquery.debug.js` & Exposed Internal Architecture

> **Severity: HIGH** — This analysis reveals exposed credentials, internal API endpoints, and architectural details that significantly expand the attack surface.

## 1. The SHA-256 Library

**File:** `script/sha256.jquery.debug.js` (247 lines, 9KB, unminified)

- **Plugin:** jQuery SHA-256 hash function (`jQuery.sha256(data)`)
- **Version:** 1.0 (debug build)
- **Author warning on line 10:** `"NOTE: This version is not tested thoroughly!"`
- **Modified by:** Jacob Bair (`orsso.zed@gmail.com`) — developer's personal email exposed in production
- **Original author:** Christoph Bichlmeier

### How It's Used

The SHA-256 function is used across the application for:
1. **MFA device comparison** — hashing email addresses to match against stored OTP device hashes
2. **Email change verification** — comparing old vs new email hashes during OTP flows
3. **OTP device selection** — verifying selected devices against hashed identifiers

### Cryptographic Weakness

Email addresses are hashed **without a salt**:

```javascript
jQuery.sha256(jQuery("#oldEmailAddr").val().toUpperCase()).toUpperCase() === c.SELECTEDOTPDEVICEHASH
```

SHA-256 of an unsalted, known-format input (email addresses) is trivially reversible via:
- Rainbow tables
- Dictionary attacks on common email patterns
- Brute force (email addresses have low entropy)

**Fix:** Use HMAC-SHA256 with a per-user salt, or better yet, handle device comparison server-side.

---

## 2. Exposed `ServiceConfig` Test Credentials

The `reliusadmin.min.js` file contains a hardcoded fallback configuration object used when `window.ServiceConfig` is not defined. This exposes:

| Field | Value | Risk |
|-------|-------|------|
| `SecId` | `045868331` | Participant ID — could be a test account or real PID |
| `GUID` | `34366362656566352D...` | Session GUID |
| `Token` | `706D5A74686D4F4D...` | Authentication token |
| `LSToken` | `593978515A374469...` | Layer security token |
| `MFAUID` | `w-wTX1RwEFN` | MFA User ID |
| `MFAPD` | `51497A576E63564132...` | MFA Password (encoded, not encrypted) |
| `CSRFToken` | `"testing"` | Hardcoded test CSRF token |
| `ServiceWebAPIURL` | `http://localhost/rawebrestservice20191` | Internal API URL revealing service name and version |
| `ParticipantPlanId` | `EFC3000` | Plan identifier |
| `AvailableOTPDevices` | `j*****@fisglobal.com\|...` | Partially masked FIS Global employee email |
| `contactId` | `7032625431487A52...` | Encrypted contact ID |
| `MfaOtpFL` | `6C344B6234573548...` | MFA OTP flag/token |
| `MfaUN` | `535834706741374D...` | Encoded MFA username |
| `MfaUInfo` | `cUW6imxnagzxU6TJ...` | Encoded MFA user info |

### Why This Matters

Even though these appear to be **test/development credentials**, they reveal:
1. The **internal API naming convention** (`rawebrestservice20191`)
2. The **encoding scheme** used for sensitive values
3. The **session token format** used for authentication
4. A **FIS Global employee email** in the OTP device list

An attacker can use this information to:
- Understand the token format and attempt forgery
- Target the internal API endpoint naming convention
- Attempt to decode the MFA credentials (they appear to be Base64/hex encoded, not properly encrypted)

---

## 3. Full REST API Endpoint Map (Exposed in Client-Side JavaScript)

The minified JavaScript reveals the complete internal API structure:

### Data Endpoints
| Method | Path | Purpose |
|--------|------|---------|
| GET/PUT | `/PersonalDatas` | Read/update personal information (name, address, DOB, SSN) |
| GET/POST | `/SponsorContactInformation` | Sponsor contact info management |
| POST | `/TransRequestCEBs` | Submit financial transactions |
| GET | `/SchwabSDBDatas` | Charles Schwab brokerage account data |
| GET | `/LoanModels` | Loan calculation and modeling |
| GET | `/MktTimingTests/RA.GetMktTimingTests` | Market timing rule validation |
| GET | `/ISOCountryCodes` | Country code lookup |
| DELETE | `/TransRequests` | Cancel transactions |
| GET | `/FeesTrading` | Fee and trading information |

### AJAX Endpoints
| Method | URL | Data | Purpose |
|--------|-----|------|---------|
| POST | `ajaxdatarequest.aspx` | `METHOD=updateselecteddevice` | Update OTP device |
| POST | `ajaxdatarequest.aspx` | `METHOD=updatehasotpdevice` | Flag OTP completion |
| POST | `ajaxdatarequest.aspx` | `METHOD=updateencryptselecteddevice` | Update encrypted device |

### Authentication Headers Used
```
X-GUID: [session GUID]
X-TOKEN: [auth token]
X-LSTOKEN: [layer security token]
X-SITEID: [site identifier]
Content-Type: application/json
```

---

## 4. MFA/OTP Flow Architecture (Exposed)

The entire Multi-Factor Authentication flow is implemented client-side and is fully visible:

### Flow Steps
```
1. User action triggers MFA check
2. Client calls IDP service with ServiceType="GetUser" 
3. IDP returns ResultStep:
   - "DISPLAYOTP" → Show OTP entry popup
   - "login" → Redirect to login (locked)
   - "NOOTPDEVICE" → No devices, show error
4. User enters OTP PIN
5. Client calls IDP with ServiceType="ValidateOtp"
6. On success (ResultStep="mfasuccess"):
   - MFASecondaryToken returned
   - Client stores token in form
   - Transaction proceeds
```

### Concerns
- **OTP validation response is trusted client-side** — the `ResultStep` values are checked in JavaScript, not enforced server-side
- **MFA secondary token** is passed back to the client and resubmitted with the transaction
- **Device selection** is done via client-side AJAX without additional server validation
- **Async: false** is used in OTP validation (`jQuery.ajax({async: false})`), blocking the UI thread
- **Error messages reveal internal architecture** ("Error calling LoanModels service", etc.)

---

## 5. Additional Exposed Information

### Schwab PCRA Integration
The code reveals a Charles Schwab Personal Choice Retirement Account integration:
- API ID, TPA ID, API Version, TPA Name are sent via hidden form POST
- Encrypted participant info is transmitted to Schwab's endpoint

### Loan Processing
Full loan request workflow exposed including:
- Amortization schedule calculations
- Repayment duration in months
- Fee calculations
- Payment methods (Check vs. EFT)
- Routing number validation

### Email Notification System
- Three email types: HOME, OFFICE, OTHER
- Email verification via OTP
- Email change triggers OTP device re-selection
- `emailAuthCd` controls whether verification is required

---

## Recommendations

### Immediate (P0 — 24 hours)
1. **Remove test credentials** from `reliusadmin.min.js` — the fallback `userInfo` object with hardcoded tokens must be stripped
2. **Replace debug SHA-256** with minified production version
3. **Add salt** to email hashing or move comparison server-side

### Short-term (P1 — 1 week)
4. **Move OTP validation server-side** — don't trust `ResultStep` in client JavaScript
5. **Remove internal API URL** (`http://localhost/rawebrestservice20191`) from client code
6. **Implement proper CSRF tokens** — `"testing"` as a CSRF token provides zero protection

### Medium-term (P2 — 1 month)
7. **API endpoint obfuscation** — consider a reverse proxy to mask internal API structure
8. **Code splitting** — don't ship admin/sponsor functionality to participant login page
9. **Proper error handling** — remove `console.log` statements that expose internal paths and data structures

---

## Disclaimer

All information in this report was obtained from **publicly accessible client-side JavaScript** served to any visitor of `https://www.accountplanaccess.com/NextLevel/default.aspx`. No authentication was bypassed, no proprietary server-side code was accessed, and no user data was obtained beyond what is visible in the page source.
