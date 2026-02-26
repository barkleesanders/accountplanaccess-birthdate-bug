# OData API Exposure — Unauthenticated $metadata & Data Leakage

> **Classification: CRITICAL** — The OData `$metadata` endpoint returns 191KB of full API schema without authentication, revealing 60+ entity types including SSN fields, plaintext password fields, and the complete data model for retirement account administration.

> **Methodology:** HTTP requests to publicly accessible endpoints using `curl`. No authentication was bypassed, no credentials were used, and no participant data was accessed.

> **Date discovered:** February 25, 2026

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [$metadata Endpoint — Full Schema Exposure](#2-metadata-endpoint--full-schema-exposure)
3. [Token Entity — Plaintext Password Field](#3-token-entity--plaintext-password-field)
4. [PersonalData Entity — Full PII Schema](#4-personaldata-entity--full-pii-schema)
5. [Financial Entity Types](#5-financial-entity-types)
6. [Unauthenticated Data Endpoints](#6-unauthenticated-data-endpoints)
7. [Pre-Auth Token Analysis](#7-pre-auth-token-analysis)
8. [Complete Entity Inventory](#8-complete-entity-inventory)
9. [Recommended Fixes](#9-recommended-fixes)

---

## 1. Executive Summary

The OData v4 REST API at `https://www.accountplanaccess.com/nextlevelapi` exposes its **complete schema** to unauthenticated visitors via the standard `$metadata` endpoint. This 191KB XML document reveals every entity type, property name, data type, and relationship in the system — including entities that handle Social Security Numbers, passwords, financial balances, loan data, and personal information.

While most data endpoints properly require authentication, the metadata itself provides an attacker with a complete blueprint of the system's data model, enabling targeted attacks.

**Key findings:**
- `$metadata` returns full OData schema (191KB) — **no authentication required**
- `Token` entity contains `passwdTxt` (plaintext password) and `ssNum` (SSN) fields
- `PersonalData` entity exposes full PII field structure (name, DOB, SSN, address, phone)
- 60+ entity types covering financial, personal, and transactional data
- `ISOCountryCodes` endpoint returns data without authentication
- Pre-auth tokens are hex-encoded AES ciphertext that rotate per request

---

## 2. $metadata Endpoint — Full Schema Exposure

### Request
```bash
curl -s "https://www.accountplanaccess.com/nextlevelapi/\$metadata"
```

### Response
- **Status:** `200 OK`
- **Authentication required:** None
- **Content-Type:** `application/xml`
- **Response size:** 191KB
- **OData version:** 4.0
- **Namespace:** `RAWebRESTService.Models` / `Relius.Admin.Web.Bus`

The response contains the complete Entity Data Model (EDM) including:
- All entity types with property names and data types
- Entity keys (primary keys revealing database structure)
- Complex types and enumerations
- Entity sets (API endpoints)
- Navigation properties (relationships between entities)

### Why This Is Critical

The `$metadata` endpoint is a standard OData feature, but for a **financial services application handling retirement accounts and SSNs**, exposing it without authentication provides attackers with:

1. **Complete data dictionary** — Every table, column name, and data type
2. **API endpoint enumeration** — All available REST endpoints
3. **Attack surface mapping** — Know exactly which endpoints handle PII, financial data, and authentication
4. **Injection targeting** — Field names and types guide SQL injection / OData injection payloads
5. **Business logic inference** — Entity relationships reveal workflow logic

---

## 3. Token Entity — Plaintext Password Field

### Schema (from $metadata)
```xml
<EntityType Name="Token">
  <Key>
    <PropertyRef Name="userNam" />
  </Key>
  <Property Name="ssNum" Type="Edm.String" />
  <Property Name="passwdTxt" Type="Edm.String" />
  <Property Name="userNam" Type="Edm.String" Nullable="false" />
  <Property Name="tokenString" Type="Edm.String" />
  <Property Name="statusCd" Type="Edm.String" />
  <Property Name="dropUser" Type="Edm.Boolean" Nullable="false" />
  <Property Name="contactId" Type="Edm.String" />
  <Property Name="adminId" Type="Edm.Int32" Nullable="false" />
</EntityType>
```

### Critical Issues

| Field | Type | Concern |
|-------|------|---------|
| `ssNum` | `Edm.String` | Social Security Number — stored/transmitted as string |
| `passwdTxt` | `Edm.String` | **PLAINTEXT PASSWORD** — field name strongly implies passwords are stored or transmitted as plaintext strings |
| `userNam` | `Edm.String` | Username — primary key for the Token entity |
| `tokenString` | `Edm.String` | Authentication token — returned after successful auth |

The `Token` entity is the **authentication endpoint** (POST only). It accepts `userNam`, `passwdTxt`, and `ssNum` to authenticate a user and return a `tokenString`.

The field name `passwdTxt` (password text) — not `passwdHash`, not `passwdDigest` — strongly implies the password is transmitted or stored as **plaintext**. Combined with the client-side `sha256.jquery.debug.js` library, the likely flow is:

1. Client hashes password with SHA-256 (no salt)
2. Sends hash as `passwdTxt` string
3. Server compares against stored hash

Even this best-case scenario uses **unsalted SHA-256** — inadequate for password storage (should be bcrypt/scrypt/Argon2).

### Token Endpoint Behavior

```bash
# GET returns 405 Method Not Allowed (correct — POST only)
curl -s "https://www.accountplanaccess.com/nextlevelapi/Token"
# → {"Message":"The requested resource does not support http method 'GET'."}

# POST with empty body returns 401 (correct — requires credentials)
curl -s -X POST "https://www.accountplanaccess.com/nextlevelapi/Token" \
  -H "Content-Type: application/json" -d '{}'
# → HTTP/2 401 (empty body)
```

The Token endpoint correctly rejects unauthenticated requests, but the schema exposure reveals the exact field names and types needed to craft authentication attempts.

---

## 4. PersonalData Entity — Full PII Schema

```xml
<EntityType Name="PersonalData">
  <Key>
    <PropertyRef Name="planId" />
    <PropertyRef Name="pid" />
  </Key>
  <Property Name="planId" Type="Edm.String" Nullable="false" />
  <Property Name="pid" Type="Edm.String" Nullable="false" />
  <Property Name="prefix" Type="Edm.String" />
  <Property Name="firstNam" Type="Edm.String" />
  <Property Name="midInitNam" Type="Edm.String" />
  <Property Name="lastNam" Type="Edm.String" />
  <Property Name="marStatCd" Type="Edm.String" />
  <Property Name="sexCd" Type="Edm.String" />
  <Property Name="birthDate" Type="Edm.DateTimeOffset" />
  <Property Name="hireDate" Type="Edm.DateTimeOffset" />
  <Property Name="street1Addr" Type="Edm.String" />
  <Property Name="street2Addr" Type="Edm.String" />
  <Property Name="cityAddr" Type="Edm.String" />
  <Property Name="stateAddr" Type="Edm.String" />
  <Property Name="zipAddr" Type="Edm.String" />
  <Property Name="cntryAddr" Type="Edm.String" />
  <Property Name="frgnStateAddr" Type="Edm.String" />
  <Property Name="phoneCntryNum" Type="Edm.String" />
  <Property Name="phoneAddr" Type="Edm.String" />
  <Property Name="phoneTextCd" Type="Edm.String" />
  <Property Name="officePhoneCntryNum" Type="Edm.String" />
  <Property Name="officePhoneAddr" Type="Edm.String" />
  <Property Name="officePhoneTextCd" Type="Edm.String" />
  <Property Name="officePhoneExt" Type="Edm.String" />
  <Property Name="otherPhoneCntryNum" Type="Edm.String" />
  <Property Name="otherPhoneAddr" Type="Edm.String" />
  <!-- ... additional fields ... -->
</EntityType>
```

This reveals that the system stores:
- Full legal name (prefix, first, middle, last)
- Date of birth, hire date
- Full mailing address (including foreign addresses)
- Three phone numbers (home, office, other) with country codes
- Marital status, sex
- Plan ID and participant ID as composite key

---

## 5. Financial Entity Types

### Distributions (Withdrawals & Terminations)
```xml
<EntityType Name="Distributions">
  <Property Name="planId" Type="Edm.String" Nullable="false" />
  <Property Name="pid" Type="Edm.String" Nullable="false" />
  <Property Name="eRISACd" Type="Edm.String" />
  <Property Name="rothVestBalAmt" Type="Edm.Decimal" Nullable="false" />
  <Property Name="nonRothVestBalAmt" Type="Edm.Decimal" Nullable="false" />
  <Property Name="employerSourceVestBalAmt" Type="Edm.Decimal" Nullable="false" />
  <Property Name="termDate" Type="Edm.DateTimeOffset" />
  <Property Name="loans" Type="Relius.Admin.Web.Bus.Models.Loans" />
  <Property Name="withdrawals" Type="RAWebRESTService.Models.Withdrawals" />
  <Property Name="terminations" Type="RAWebRESTService.Models.Terminations" />
</EntityType>
```

### Additional Financial Entities
| Entity | Data Exposed |
|--------|-------------|
| `ContributionRate` | Employee contribution rates and elections |
| `LoanModel` / `NewLoan` | Loan calculations, repayment schedules |
| `Transfer` | Fund-to-fund transfer requests |
| `Rebalance` | Portfolio rebalancing data |
| `MyPortfolioData` | Current investment portfolio |
| `TransactionFile` | Transaction history |
| `Election` / `Election403b` | Investment election data |
| `RetirementIncomeCalc` | Retirement income projections |
| `SchwabSDBData` | Charles Schwab brokerage account integration |
| `FeeTrading` / `FeeTradingFunds` | Fee and trading information |
| `TransLedData` / `TransLedpayment` | Transaction ledger and payments |

---

## 6. Unauthenticated Data Endpoints

### ISOCountryCodes — Data Returned Without Auth

```bash
curl -s "https://www.accountplanaccess.com/nextlevelapi/ISOCountryCodes"
```

Returns full country code dataset (248 countries) without any authentication:

```json
{
  "@odata.context": "https://www.accountplanaccess.com/nextlevelapi/$metadata#ISOCountryCodes",
  "value": [
    {"isocntrycd": "840", "isocntrynam": "United States of America", "isoalphA2CD": "US", ...},
    {"isocntrycd": "826", "isocntrynam": "United Kingdom", "isoalphA2CD": "GB", ...},
    ...
  ]
}
```

While this is reference data with low sensitivity, it confirms that **not all OData endpoints enforce authentication**. Any newly added reference data endpoints could inadvertently be exposed.

### Endpoints That Properly Require Auth

Most data endpoints return `"No HTTP resource was found"` without an authenticated session, indicating the OData routes are **dynamically registered per session** — a positive defense-in-depth pattern. Tested endpoints:

| Endpoint | Response (Unauth) |
|----------|------------------|
| `/PersonalDatas` | No HTTP resource found |
| `/Distributions` | No HTTP resource found |
| `/Elections` | No HTTP resource found |
| `/Transfers` | No HTTP resource found |
| `/LoanModels` | No HTTP resource found |
| `/TransactionFiles` | No HTTP resource found |
| `/ContributionRates` | No HTTP resource found |
| `/ParticipantStatuses` | No HTTP resource found |
| `/Documents` | No HTTP resource found |

### API Root — Properly Secured

```bash
curl -s "https://www.accountplanaccess.com/nextlevelapi/"
# → {"error":{"code":"","message":"Authorization has been denied for this request."}}
```

---

## 7. Pre-Auth Token Analysis

### Token Generation
Every unauthenticated request to `/NextLevel/` generates fresh `Token`, `LSToken`, and `Sid` values embedded in the HTML.

### Token Format
The tokens are **hex-encoded**, and when decoded reveal AES ciphertext:

```
Raw hex:  4661456C4555314668325673535743535731665473413D3D...
Decoded:  FaElEU1Fh2VsSWCSW1fTsA==uEqcPPfkDQnWUZ0d33SsD53gP2ooomPe/lGtmsZaW0gA
Format:   <base64-IV>==<base64-ciphertext>
```

### Token Rotation
Tokens **rotate on every request** — each page load generates a new set:

| Request | Token (first 16 chars) | Sid (first 16 chars) |
|---------|----------------------|---------------------|
| 1st | `FaElEU1Fh2VsSWCS` | `g/C5OodbgDVRsfGC` |
| 2nd | `6J8TPb7+j3AiDMMd` | `5FtsxjCAA5tlzoUq` |
| 3rd | `XiZ7NsZkBl4Kk9+T` | `fewppB3CkQT2p60W` |

### Static Values
- `ServiceSiteId` is **static** across all requests: `f77b9ff7-1c84-4e14-ac51-ae67bb908b58`
- `MfaProvider` is always `E`
- `MfaEnabled` is always `false`

### Pre-Auth Token Access Test
The harvested pre-auth tokens do **not** bypass API authentication:

```bash
curl -s "https://www.accountplanaccess.com/nextlevelapi/" \
  -H "Token: FaElEU1Fh2VsSWCSW1fTsA==..." \
  -H "ServiceSiteId: f77b9ff7-1c84-4e14-ac51-ae67bb908b58"
# → {"error":{"code":"","message":"Authorization has been denied for this request."}}
```

However, the server still generates these tokens for every anonymous request, consuming server-side resources (cryptographic operations, session table entries).

---

## 8. Complete Entity Inventory

### All 60+ Entity Types Exposed via $metadata

#### Authentication & Configuration
| Entity | Fields of Interest |
|--------|--------------------|
| `Token` | `ssNum`, `passwdTxt`, `userNam`, `tokenString`, `adminId` |
| `ConfigSetting` | `name`, `boolValue`, `dateTimeValue`, `stringValue` |
| `ConfigSettingDefinition` | `name`, `type`, `location`, `defaultValue` |

#### Personal Information
| Entity | Fields of Interest |
|--------|--------------------|
| `PersonalData` | Full name, DOB, address, phone, marital status, sex |
| `PersonalDataConfiguration` | Configuration for PII display/editing |
| `ParticipantStatus` | Participant employment/plan status |
| `GeneralParticipantFile` | General participant records |

#### Financial Data
| Entity | Fields of Interest |
|--------|--------------------|
| `Distributions` | Roth/non-Roth vested balances, termination data |
| `ContributionRate` | Employee contribution rates |
| `LoanModel` / `NewLoan` | Loan calculations and applications |
| `Transfer` | Fund transfer requests |
| `Rebalance` / `RebalanceOptions` | Portfolio rebalancing |
| `MyPortfolioData` / `MyPortfolioLayout` | Current investment portfolio |
| `MyPortfolio403bLayout` / `MyPortfolio403bData` | 403(b) portfolio data |
| `RetirementIncomeCalc` | Retirement income projections |
| `Election` / `Election403b` | Investment elections |
| `InvestProductDetail` | Investment product information |
| `FundFactSheet` | Fund documentation |
| `FeeTrading` / `FeeTradingFunds` | Fee schedules and trading data |
| `RedemptionFee` | Redemption fee data |
| `TradeRestriction` | Trading restriction rules |
| `MktTimingTest` | Market timing test rules |
| `AddInvestProvider` | Investment provider management |
| `SchwabSDBData` / `SDBDetail` | Charles Schwab brokerage integration |
| `AvailFundsElect` / `AvailFundsTrnsf` | Available funds for elections/transfers |

#### Transactions
| Entity | Fields of Interest |
|--------|--------------------|
| `TransactionFile` | Transaction history |
| `TransactionCertification` | Transaction certification records |
| `TransRequest` | Transaction requests |
| `TransRequestCEB` | CEB transaction requests |
| `TransRequestContrElection` | Contribution election changes |
| `TransRequestCTT` | CTT transaction requests |
| `TransRequestElection` / `TransRequestElection403B` | Election change requests |
| `TransRequestLoan` / `TransRequestLoanLOC` | Loan requests / lines of credit |
| `TransRequestTermination` | Termination transaction requests |
| `TransRequestTransfer` | Transfer requests |
| `TransRequestWithdrawal` | Withdrawal requests |
| `TransLedData` / `TransLedpayment` | Transaction ledger data |

#### Administration
| Entity | Fields of Interest |
|--------|--------------------|
| `PlanStat` | Plan statistics |
| `PlanVoiceQuery` | Voice/IVR query data |
| `SponsorContactInformations` | Plan sponsor contact info |
| `ContractDetail` | Contract/plan details |
| `Document` | Document management |
| `WebBinFile` | Binary file storage |
| `WWWTrackingLog` | User activity tracking logs |
| `STPReportJobStatus` | Report generation status |
| `VoiceUpdateData` | Voice/IVR update records |
| `CTT` | CTT records |
| `ISOCountryCodes` | Country code reference data |

---

## 9. Recommended Fixes

### Immediate (P0 — 24 hours)

#### Fix 1: Restrict $metadata Endpoint
The `$metadata` endpoint must require authentication:

```csharp
// In WebApiConfig.cs or OData configuration
// Option A: Require authentication for $metadata
config.MapODataServiceRoute("odata", "nextlevelapi", builder =>
{
    builder.AddService(ServiceLifetime.Singleton, sp => model);
    // Add authorization filter for metadata
});

// Option B: In web.config, restrict the endpoint
```

```xml
<!-- web.config -->
<location path="nextlevelapi/$metadata">
  <system.web>
    <authorization>
      <deny users="?" />
    </authorization>
  </system.web>
</location>
```

#### Fix 2: Rename Token Entity Fields
The `passwdTxt` field name should be changed to avoid implying plaintext storage:

```csharp
// Before
public string passwdTxt { get; set; }

// After — if using hashed passwords
public string passwdHash { get; set; }
```

Ensure passwords are hashed with **bcrypt/scrypt/Argon2** server-side, not just SHA-256.

### Short-term (P1 — 1 week)

#### Fix 3: Require Auth for All OData Endpoints
Add a global authorization filter to the OData pipeline:

```csharp
// Global OData authorization attribute
[Authorize]
public class SecureODataController : ODataController
{
    // All OData endpoints inherit authentication requirement
}
```

#### Fix 4: Restrict ISOCountryCodes Endpoint
Even reference data should require authentication on a financial platform:

```csharp
[Authorize]
public IQueryable<ISOCountryCodes> GetISOCountryCodes()
{
    return db.ISOCountryCodes;
}
```

#### Fix 5: Rate-Limit Pre-Auth Token Generation
Implement rate limiting on `/NextLevel/` to prevent token harvesting:

```xml
<!-- IIS Dynamic IP Restrictions -->
<system.webServer>
  <security>
    <dynamicIpSecurity>
      <denyByConcurrentRequests enabled="true" maxConcurrentRequests="10" />
      <denyByRequestRate enabled="true" maxRequests="20" requestIntervalInMilliseconds="2000" />
    </dynamicIpSecurity>
  </security>
</system.webServer>
```

### Medium-term (P2 — 1 month)

#### Fix 6: Implement Proper Password Storage
Replace SHA-256 password hashing with a proper key derivation function:

```csharp
// Use BCrypt.Net-Next NuGet package
using BCrypt.Net;

// Hash password
string hash = BCrypt.HashPassword(password, workFactor: 12);

// Verify password
bool valid = BCrypt.Verify(password, storedHash);
```

#### Fix 7: OData Query Restrictions
Add `$select`, `$filter`, `$expand` restrictions to prevent excessive data exposure:

```csharp
[Page(MaxTop = 100)]
[Select(SelectType = SelectExpandType.Disabled)]
public class PersonalDatasController : ODataController
{
    // Restrict which fields can be queried
}
```

---

## Finding Summary

| # | Severity | Finding | CVSS Est. |
|---|----------|---------|-----------|
| 1 | **CRITICAL** | `$metadata` exposes full 191KB API schema without authentication | 7.5 |
| 2 | **CRITICAL** | Token entity schema reveals `passwdTxt` (plaintext password) and `ssNum` (SSN) fields | 8.2 |
| 3 | **HIGH** | PersonalData entity exposes full PII field structure | 7.0 |
| 4 | **HIGH** | 60+ entity types expose complete financial data model | 7.0 |
| 5 | **MEDIUM** | `ISOCountryCodes` endpoint returns data without authentication | 5.0 |
| 6 | **MEDIUM** | Pre-auth tokens consume server resources on every anonymous request | 5.3 |
| 7 | **LOW** | Token format analysis reveals AES encryption pattern | 3.5 |

---

## Disclaimer

This analysis was performed using only **standard HTTP requests** to publicly accessible endpoints. No authentication was bypassed, no credentials were guessed or brute-forced, no participant data was accessed, and no exploitation was attempted. The `$metadata` endpoint is a standard OData feature that responds to any unauthenticated HTTP GET request. All findings are based on information voluntarily served by the web server.

This report is provided in good faith for responsible security disclosure purposes.
