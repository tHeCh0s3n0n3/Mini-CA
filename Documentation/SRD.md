# Mini CA Software Requirements Document (SRD)

## 1. Introduction

### 1.1 Purpose
This document specifies the software requirements for **Mini CA**, an internal Public Key Infrastructure (PKI) system designed to manage Certificate Signing Requests (CSRs) and issue X.509 v3 certificates. It serves as a centralized authority for securing internal infrastructure via HTTPS.

### 1.2 Scope
Mini CA provides a self-service portal for users to submit CSRs, an administrative backend for approving and signing requests, and an automated ACME server for infrastructure components.

## 2. Overall Description

### 2.1 System Architecture
The system employs a decoupled, multi-tiered architecture based on ASP.NET Core MVC and OpenID Connect:

*   **Frontend (User Portal):** A public-facing web interface acting as a Registration Authority (RA). It accepts `.csr` uploads, displays request history, and provides instructions for trusting the Root CA.
*   **Backend (Admin Portal):** A secure administrative interface acting as the Certificate Authority (CA). It allows authorized users to manage CSRs, ACME EAB credentials, and audit logs.
*   **ACME Server:** An RFC 8555 compliant server integrated into the Backend, allowing automated issuance for tools like Traefik and Certbot via External Account Binding (EAB).
*   **Data Access Layer (DAL):** A shared Entity Framework Core library managing persistence to two SQLite databases: `db.sqlite` (CSRs, EABs, Audit Logs) and `identity.sqlite` (OIDC User cache).
*   **Common Library:** A shared library encapsulating core cryptographic operations (BouncyCastle) and AES-256 encryption for secrets.

### 2.2 Illustrative Figure: System Flow

```ascii
                      +-------------------+
                      |                   |
    .csr upload       |  Frontend Web App |       Extracts CSR metadata
   ------------------>|  (User Portal)    |-----\ (CN, O, SANs, etc.)
  |                   |                   |     |
  |                   +-------------------+     v
[User]                                    +------------+
                                          |            |
                                          | SQLite DB  |
[Admin]                                   |            |
  |                   +-------------------+     ^
  |                   |                   |     |
   ------------------>|  Backend Web App  |-----/ Reads pending CSRs,
    Auth via Authentik|  (Admin Portal)   |       EABs & Audit Logs
                      |                   |
                      +-------------------+
                               |
                               | Initiates Signing Process
                               v
                      +-------------------+
    Requires local    |                   |
    CA Cert &         | BouncyCastle      |-----> Generates .crt
    Encrypted CA Key  | Crypto Engine     |       (X.509 v3 Certificate)
                      |                   |
                      +-------------------+
```

## 3. Specific Requirements

### 3.1 Functional Requirements

*   **REQ-1 (CSR Upload):** The Frontend shall allow users to upload PKCS#10 CSR files.
*   **REQ-2 (User Dashboard):** The Frontend shall display a history of CSRs submitted by the authenticated user, including signing status and expiration alerts.
*   **REQ-3 (Multi-Format Download):** The system shall allow users to download signed certificates in PEM (.crt), DER (.cer), and P7B (with chain) formats.
*   **REQ-4 (ACME Server):** The Backend shall provide an ACME v2 compliant directory for automated certificate lifecycle management.
*   **REQ-5 (EAB Restriction):** ACME registration shall be restricted to pre-provisioned accounts using External Account Binding (EAB).
*   **REQ-6 (Identifier Whitelisting):** ACME EAB records shall support Regex patterns to restrict allowable FQDNs or IP addresses.
*   **REQ-7 (Audit Logging):** The system shall maintain an immutable log of all certificate issuance events (Manual and ACME).
*   **REQ-8 (Root CA Distribution):** The Frontend shall provide dynamic instructions and scripts for installing the Root CA on Windows, Linux, Chrome, and Android.

### 3.2 Security and Authentication Requirements

*   **Authentication Method:** Both portals enforce authentication via **Authentik (OpenID Connect)**.
*   **Authorization:** Backend access is restricted to users in the `admin` group.
*   **Secret Protection:** EAB HMAC keys are encrypted at rest using **AES-256**. The master encryption key is read from a local file.
*   **CA Key Protection:** The Root CA private key password is read from a separate, secured local file.

## 4. Technology Stack & Dependencies

*   **Runtime:** .NET 10.0
*   **Web Framework:** ASP.NET Core MVC
*   **ACME Provider:** OpenCertServer.Acme
*   **Crypto Engine:** BouncyCastle
*   **Database:** Entity Framework Core + SQLite

## 5. Setup Instructions

### 5.1 Authentik Setup
1.  **Create Provider:** Resources > Providers > Create "OAuth2/OpenID Provider".
    *   **Name:** `MiniCA`
    *   **Client Type:** `Confidential`
    *   **Redirect URIs:** `https://<your-domain>/signin-oidc`
2.  **Create Application:** Resources > Applications > Create Application.
    *   **Name:** `Mini CA`
    *   **Provider:** Select `MiniCA`.
3.  **Scopes:** Ensure `openid`, `profile`, `email`, and `groups` are enabled.
4.  **Admin Group:** Ensure an `admin` group exists and relevant users are members.

### 5.2 Encryption Key Generation
For EAB HMAC protection, generate a 32-byte Base64 string and save it to the file specified in `Acme:MasterKeyPath`:

```bash
# Linux
openssl rand -base64 32 > master.key

# PowerShell
$bytes = New-Object Byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
[Convert]::ToBase64String($bytes) | Out-File -FilePath "master.key" -Encoding utf8
```

## 6. Configuration (appsettings.json)

### 6.1 Settings Explanation

| Setting | Description | Example |
| :--- | :--- | :--- |
| `Authentik:Authority` | The OIDC discovery URL for Authentik. | `https://auth.domain.com/application/o/minica/` |
| `Authentik:ClientId` | The Client ID from Authentik. | `minica-client-id` |
| `Authentik:ClientSecret` | The Client Secret from Authentik. | `your-long-secret` |
| `Acme:BaseUri` | The external URL of your Mini CA instance. | `https://minica.internal.com` |
| `Acme:MasterKeyPath` | Path to the 32-byte Base64 master key file. | `C:\Keys\master.key` |
| `CACert:CertFilePath` | Path to the public Root CA certificate. | `/etc/minica/ca.crt` |
| `CACert:CertKeyFilePath` | Path to the Root CA private key. | `/etc/minica/ca.key` |
| `CACert:CertKeyPasswordFilePath` | Path to the file containing the CA key password. | `/etc/minica/ca.key.passwd` |

### 6.2 Full Example (Backend)
```json
{
  "ConnectionStrings": {
    "SQLiteConnection": "Data Source=/app/data/db.sqlite;Cache=Shared;",
    "IdentityConnection": "Data Source=/app/data/identity.sqlite;Cache=Shared;"
  },
  "Authentik": {
    "Authority": "https://authentik.company.com/application/o/minica/",
    "ClientId": "my-client-id",
    "ClientSecret": "my-client-secret"
  },
  "Acme": {
    "BaseUri": "https://minica.local",
    "MaxOrdersPerMinute": 10,
    "MasterKeyPath": "/app/secrets/master.key"
  },
  "CACert": {
    "CertFilePath": "/app/secrets/ca.crt",
    "CertKeyFilePath": "/app/secrets/ca.key",
    "CertKeyPasswordFilePath": "/app/secrets/ca.key.passwd"
  }
}
```

### 6.3 Full Example (Frontend)
```json
{
  "ConnectionStrings": {
    "SQLiteConnection": "Data Source=/app/data/db.sqlite;Cache=Shared;",
    "IdentityConnection": "Data Source=/app/data/identity.sqlite;Cache=Shared;"
  },
  "Authentik": {
    "Authority": "https://authentik.company.com/application/o/minica/",
    "ClientId": "my-client-id",
    "ClientSecret": "my-client-secret"
  },
  "CACert": {
    "CertFilePath": "/app/secrets/ca.crt"
  }
}
```
