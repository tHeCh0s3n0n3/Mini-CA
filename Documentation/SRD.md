# Mini CA Software Requirements Document (SRD)

## 1. Introduction

### 1.1 Purpose
This document specifies the software requirements for **Mini CA**, an internal Public Key Infrastructure (PKI) system designed to manage Certificate Signing Requests (CSRs) and issue X.509 v3 certificates. It serves as a centralized authority for securing internal infrastructure via HTTPS.

### 1.2 Scope
Mini CA provides a self-service portal for users to submit CSRs and an administrative backend for approving and signing those requests using a trusted internal Root Certificate Authority (CA) key.

## 2. Overall Description

### 2.1 System Architecture
The system employs a decoupled, multi-tiered architecture based on ASP.NET Core MVC:

*   **Frontend (User Portal):** A public-facing web interface acting as a Registration Authority (RA). It accepts `.csr` uploads, parses their contents, and stores the pending requests.
*   **Backend (Admin Portal):** A secure administrative interface acting as the Certificate Authority (CA). It allows authorized users to review pending CSRs, specify key usages, set expiration dates, and cryptographically sign the certificates.
*   **Data Access Layer (DAL):** A shared Entity Framework Core library managing persistence to a SQLite database (`db.sqlite`).
*   **Common Library:** A shared library encapsulating core cryptographic operations, abstracting complex interactions with the BouncyCastle PKI engine.

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
   ------------------>|  Backend Web App  |-----/ Reads pending CSRs &
    Auth via Nextcloud|  (Admin Portal)   |       Saves Signed Certs
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

*   **REQ-1 (CSR Upload):** The Frontend shall allow users to upload PKCS#10 Certificate Signing Requests (`.csr` files).
*   **REQ-2 (CSR Parsing):** The system shall parse uploaded CSRs to extract standard X.509 attributes, including Country (C), Organization (O), Organizational Unit (OU), Common Name (CN), Locality (L), State/Province (ST), Email (E), and Subject Alternative Names (SANs).
*   **REQ-3 (CSR Validation):** The system shall cryptographically verify the signature of the uploaded CSR before accepting it.
*   **REQ-4 (Admin Dashboard):** The Backend shall display a list of all submitted CSRs, indicating their signing status.
*   **REQ-5 (Certificate Signing):** The Backend shall allow administrators to sign pending CSRs using a configured CA certificate and private key.
*   **REQ-6 (Extension Configuration):** During the signing process, administrators shall be able to configure the certificate's validity period, Key Usages, and Extended Key Usages.
*   **REQ-7 (Certificate Download):** The system shall allow administrators to download the resulting signed X.509 certificate (`.crt` file).
*   **REQ-8 (Deletion):** Administrators shall be able to delete pending or processed CSR records from the database.

### 3.2 Security and Authentication Requirements

*   **Authentication Method:** The Backend portal shall enforce authentication via **Nextcloud OAuth 2.0**.
*   **Authorization:** Access to the Backend portal shall be strictly limited to users authenticated via Nextcloud who are members of the designated `admin` group (enforced via `AdminAuthorizationFilterAttribute`).
*   **Key Protection:** The CA Private Key shall be stored securely on the filesystem, separate from the application code. It must be encrypted, and the decryption password must be read from a separate, secured file (`CAKeyPasswordFinder`).
*   **Strong Typing:** The system shall use Strongly-Typed IDs (e.g., `CSRId`, `SignedCSRId`) to prevent ID manipulation and transposition errors in data access.

## 4. Technology Stack & Dependencies

### 4.1 Frameworks
*   **Runtime:** .NET 10.0
*   **Web Framework:** ASP.NET Core MVC (Frontend and Backend)
*   **ORM:** Entity Framework Core

### 4.2 Key Libraries
*   **Portable.BouncyCastle:** Core cryptographic engine for parsing CSRs, generating random numbers, building X.509 v3 certificates, and creating RSA signatures.
*   **Microsoft.EntityFrameworkCore.Sqlite:** Database provider for SQLite.
*   **AspNet.Security.OAuth.Nextcloud:** OAuth 2.0 provider for Nextcloud integration.
*   **Microsoft.AspNetCore.Identity:** Core identity management framework.
*   **Serilog (and Serilog.Sinks.File):** Structured logging framework.

### 4.3 Infrastructure
*   **Database:** SQLite (Primary application data in `db.sqlite`, Identity data likely in a separate context).
