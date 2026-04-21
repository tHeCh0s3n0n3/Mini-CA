# Mini CA Enhancements Design Specification

**Date:** 2026-03-20
**Status:** Approved

## 1. Executive Summary
This document specifies three major enhancements to the Mini CA solution:
1.  Replacement of Nextcloud OAuth with Authentik OIDC.
2.  Implementation of a restricted ACME server using External Account Binding (EAB).
3.  Transformation of the Frontend into a user dashboard with CA trust instructions.

## 2. Authentication: Authentik OIDC
The existing Nextcloud-specific authentication will be replaced with a standards-compliant OpenID Connect (OIDC) integration.

### 2.1 Authentik Setup Requirements
*   **Provider:** OAuth2/OpenID Provider with `groups` scope enabled.
*   **Client Configuration:** Confidential client type, Redirect URI `https://<host>/signin-oidc`.
*   **Claims:** `groups` claim must be present in the ID token or userinfo endpoint.
*   **Authorization:** The `admin` group membership determines access to the Backend portal.

### 2.2 Technical Implementation
*   **Backend:** Replace `AddNextcloud` with `AddOpenIdConnect`.
*   **Authorization Filter:** Update `AdminAuthorizationFilterAttribute` to check for the `groups` claim.
*   **Frontend:** Introduce `AddOpenIdConnect` to ensure user identity is tracked for CSR ownership.

## 3. ACME Protocol Support
Automated certificate issuance via ACME (RFC 8555), restricted to internal infrastructure.

### 3.1 External Account Binding (EAB)
To prevent unauthorized use, public registration is disabled.
*   **Mechanism:** Accounts must be pre-provisioned in the database.
*   **Credentials:** Each infrastructure component (Traefik/Certbot) will use a unique Key ID (KID) and HMAC Key.
*   **Server Framework:** `OpenCertServer.Acme` (or compatible ASP.NET Core middleware).

### 3.2 Issuance Logic
The ACME challenge verification will trigger the existing `Common.Certificate.SignCSR` logic using the Root CA key.

### 3.3 ACME EAB Management (Admin Portal)
A new administrative interface will be added to the Backend to manage pre-provisioned ACME credentials.
*   **AcmeEab Model:** Stores KID, Encrypted HMAC Key, Description, AllowedIdentifierPattern (Regex), Creation Date, `LastUsedAt`, and `UsageCount`.
*   **Identifier Whitelisting:** Supports both FQDNs and IP addresses via Regex validation in the signing pipeline.
*   **Key Protection:** HMAC keys are encrypted at rest using a Master Key read from a local file.
*   **Management Actions:**
    *   **List:** View all active EAB records and their usage metadata.
    *   **Create:** Generate a new KID/HMAC pair.
        *   **UI:** Display HMAC once; provide a "Download as JSON/Text" button for secure storage.
    *   **Revoke:** Delete an EAB record.

### 3.4 ACME Operational Constraints
*   **Rate Limiting:** Configurable via `appsettings.json` (e.g., `Acme:MaxOrdersPerMinute`).
*   **Directory URL:** Prominently displayed in both Backend and Frontend for easy client configuration.

## 4. Frontend User Dashboard
The current single-page upload form will be expanded into a multi-purpose dashboard.

### 4.1 Data Model Changes
*   **CSR Entity:** Add `UserId` string property to store the OIDC `sub` or `email` claim.
*   **AcmeEab Entity:** New entity to store pre-provisioned ACME credentials.
*   **AcmeAccount Entity:** New entity to track ACME accounts registered via EAB.
*   **AuditLog Entity (New):** Records all issuance events (Manual & ACME) for traceability. Includes Timestamp, Actor (Admin or ACME Account), Action, and Subject.

### 4.2 Dashboard Table
Columns (in order):
1.  **Request Timestamp**: `yyyy-MM-dd HH:mm:ss` (Local timezone).
2.  **Subject**: `CN` and `SANs` (One per line).
3.  **Status**: `Pending`, `Signed`, `Expiring Soon` (⚠️ icon), or `Expired` (❌ icon, row greyed out).
4.  **Download Actions**: Multi-format buttons (PEM, DER, P7B).

### 4.3 Root CA Trust Instructions
A dedicated section providing:
*   **UI:** A dropdown menu to select the OS/Platform (Windows, Linux, Chrome, Android).
*   **Dynamic Content:** Only the instructions for the selected platform are displayed.
    *   **Windows (PowerShell):** `Import-Certificate -FilePath "rootca.crt" -CertStoreLocation Cert:\LocalMachine\Root`
    *   **Linux (Bash):** `sudo cp rootca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`
    *   **Browsers/Mobile:** Guided text for manual installation.

## 5. Out of Scope
The following features are identified for future consideration but are not part of the current implementation:
*   **Email Notification System:** Automated alerts for expiring certificates.
*   **HSM Integration:** Storing CA keys in hardware modules.
*   **Auto-Revocation:** OCSP/CRL automation for ACME-issued certs.

## 6. Technology Stack Summary
*   **Framework:** .NET 10.0
*   **Auth:** Microsoft.AspNetCore.Authentication.OpenIdConnect
*   **ACME:** OpenCertServer.Acme
*   **Crypto:** BouncyCastle + AES-256 (for EAB key encryption)
*   **Database:** SQLite (EF Core)
