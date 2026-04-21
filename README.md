# Mini CA

**Mini CA** is a custom internal Public Key Infrastructure (PKI) and Certificate Authority (CA) system. It is designed to secure internal infrastructure via HTTPS by providing a self-service user portal for manual CSR signing and an automated ACME server for infrastructure components.

## 🚀 Key Features
*   **User Dashboard:** Upload CSRs, track signing status, and download certificates in PEM, DER, and P7B formats.
*   **Admin Portal:** Manage manual CSR signing, ACME External Account Binding (EAB) credentials, and view immutable audit logs.
*   **Hardened ACME:** RFC 8555 compliant server with mandatory EAB and identifier whitelisting (Regex-based).
*   **Authentik OIDC:** Secure authentication and group-based authorization via Authentik.
*   **Docker Ready:** Easily deployable using Docker Compose.

---

## 🏗️ Architecture
*   **Frontend:** User portal for certificate lifecycle management.
*   **Backend:** Admin portal and ACME directory.
*   **DAL:** Data Access Layer using dual SQLite databases (`db.sqlite` and `identity.sqlite`).
*   **Common:** Shared cryptographic logic using BouncyCastle and AES-256 encryption.

---

## 🛠️ Setup Guide

### 1. Prerequisites
*   Docker and Docker Compose.
*   An [Authentik](https://goauthentik.io/) instance.
*   A Root CA Certificate (`ca.crt`) and Private Key (`ca.key`).

### 2. Prepare Secrets
Create a `secrets/` directory and provision the required files:

```bash
mkdir -p secrets
# 1. Generate the Master Key for EAB HMAC encryption
openssl rand -base64 32 > secrets/master.key

# 2. Add your CA files (DO NOT COMMIT THESE)
# secrets/ca.crt
# secrets/ca.key
# secrets/ca.key.passwd
```

### 3. Authentik Configuration
1.  **Create an OIDC Provider** in Authentik.
    *   **Redirect URI:** `http://localhost:8080/signin-oidc` (Frontend) and `http://localhost:8081/signin-oidc` (Backend).
2.  **Create a Group** named `admin`. Users in this group will have access to the Backend.
3.  **Map Claims:** Ensure the `groups` scope is enabled so Mini CA can verify admin status.

### 4. Configure App Settings
Update `Backend/appsettings.json` and `Frontend/appsettings.json` with your Authentik `ClientId`, `ClientSecret`, and `Authority`.

### 5. Deployment
Launch the solution using Docker Compose:
```bash
docker-compose up -d --build
```
*   **User Portal:** `http://localhost:8080`
*   **Admin Portal:** `http://localhost:8081`

---

## 👤 User Management

### Creating your first user
Mini CA uses Authentik as the source of truth. You do not need to create users manually in the app:
1.  Navigate to the User Portal or Admin Portal.
2.  Click **Log In**.
3.  Sign in via Authentik. The system will automatically register your identity.
4.  To grant **Admin Access**, simply add the user to the `admin` group in Authentik.

---

## 🛡️ ACME & EAB Management

### How to whitelist domains for ACME
1.  Log in to the **Admin Portal** (`http://localhost:8081`).
2.  Navigate to **ACME EAB**.
3.  Click **Create New EAB**.
4.  In the **Allowed Identifier Pattern** field, enter a Regex.
    *   *Example:* `.*\.tarekfadel\.com$` allows any subdomain of `tarekfadel.com`.
    *   *Example:* `^myapp\.internal\.local$` restricted to one specific domain.
5.  Save the record and copy the **Key ID (KID)** and **HMAC Key** (displayed only once) for your ACME client (Certbot, Traefik, etc.).

---

## 📝 Documentation
For more detailed information, see the `Documentation/` directory:
*   [Software Requirements Document (SRD)](Documentation/SRD.md)
*   [Enhancements Design Spec](Documentation/specs/2026-03-20-minica-enhancements-design.md)
*   [Docker Deployment Guide](Documentation/docker-push-instructions.md)
