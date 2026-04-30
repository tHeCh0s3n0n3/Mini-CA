# Mini CA Project Context

## Project Overview
**Mini CA** is a custom internal Public Key Infrastructure (PKI) and Certificate Authority (CA) system designed to secure internal infrastructure via HTTPS. It provides both a self-service user portal and an administrative backend, along with automated certificate issuance via the ACME protocol.

### Key Technologies
- **Runtime:** .NET 10.0
- **Web Framework:** ASP.NET Core MVC
- **Cryptography:** BouncyCastle (Granular X.509 operations)
- **ACME Server:** OpenCertServer (RFC 8555 compliant)
- **Authentication:** Authentik (OpenID Connect)
- **Data Access:** Entity Framework Core with dual SQLite databases (`db.sqlite` for application data, `identity.sqlite` for user identity).
- **Architecture:** Multi-tiered (Frontend, Backend, DAL, Common)

## Project Structure
- **Frontend/:** User dashboard for CSR submission, certificate downloads (PEM, DER, P7B), and Root CA trust instructions.
- **Backend/:** Administrative portal for manual CSR signing, ACME External Account Binding (EAB) management, and immutable audit logs.
- **DAL/:** Shared Data Access Layer containing models (`CSR`, `AcmeEab`, `AuditLog`, etc.) and EF Core context.
- **Common/:** Shared library for core cryptographic logic and AES-256 secret encryption.
- **Documentation/:** Contains the Software Requirements Document (SRD), design specifications, and implementation plans.

## Building and Running

### Prerequisites
- .NET 10 SDK
- `dotnet-ef` tool installed (`dotnet tool install --global dotnet-ef`)
- Authentik instance for OIDC authentication.

### Key Commands
- **Build Solution:** `dotnet build`
- **Run Frontend:** `dotnet run --project Frontend`
- **Run Backend:** `dotnet run --project Backend`
- **Database Migrations:** 
  `dotnet ef migrations add <Name> --project DAL --startup-project Backend --context DB`
- **Update Database:** 
  `dotnet ef database update --project DAL --startup-project Backend --context DB`

## CI/CD and DevOps
- **GitHub Actions:** Automated Docker builds are triggered on git tags (e.g., `v1.0.0-alphaX`).
  - **Registry:** Pushes to `ghcr.io` as `mini-ca-frontend` and `mini-ca-backend`.
  - **Tags:** Each build is tagged with both `:latest` and the specific git tag name.
- **Docker Healthchecks:** Both Frontend and Backend containers include healthchecks using `curl` against local `/health` endpoints.

## UI and Aesthetics
- **Dark Mode:** Native dark mode is enabled by default with a user-toggle available in the navigation bar. Theme preference is persisted in `localStorage`.
- **Brand Customization:** 
  - **Color Scheme:** Primary accents and buttons use the brand color `RGB(253, 216, 53)` (#FDD835).
  - **Logo:** Customizable via `Site:LogoUrl` in `appsettings.json`.
  - **Favicon:** Brand-consistent SVG favicon (`favicon.svg`).

## Configuration Overrides
The system supports several overrides via `appsettings.json` or environment variables:
- **Admin Groups:** `Authentik:AdminGroups` (Array, defaults to `["admin"]`) allows specifying which Authentik groups grant backend access.
- **ACME Directory:**
  - `Acme:DirectoryHostname`: Overrides the ACME directory hostname shown to users.
  - `Acme:DirectoryPath`: Overrides the path (defaults to `/acme/directory`).
- **Site Branding:** `Site:LogoUrl` for the navigation bar logo.

## Development Workflow

### Tool Verification
- **Verify Tools First:** Before starting any task, explicitly verify that required tools (e.g., `dotnet`, `git`, `dotnet-ef`) are installed and accessible in the current environment. 

### Git & Commit Standards
- **Build Before Commit:** A successful build (`dotnet build`) with **zero errors** and **zero nullable warnings** is a mandatory prerequisite for any git commit. 
- **Atomic Commits:** Prefer small, focused commits that correspond to specific tasks in an implementation plan.
- **Tagging Discipline:** Do NOT tag a new release for non-functional changes (e.g., documentation, comments, `docker-compose.yaml` tweaks) to avoid unnecessary CI/CD image builds.

## Development Conventions

### Coding Style & Standards
- **Strongly-Typed IDs:** Uses the `StronglyTypedId` package to prevent primitive obsession (e.g., `CSRId` instead of `Guid`).
- **Nullable Safety:** `#nullable enable` should be used in all new or modified files. Treat nullable warnings as errors.
- **Asynchronous Patterns:** Use `async/await` for all I/O and database operations.
- **Time Handling:** ALWAYS use `DateTime.UtcNow` for timestamps and validity checks to ensure consistency across audit logs and certificate lifecycle.
- **Logging:** Structured logging via **Serilog**.

### Security Practices
- **Secret Protection:** EAB HMAC keys are encrypted at rest using AES-256. The master key must be stored in a local file (referenced in `appsettings.json`) and never committed.
- **CA Protection:** The Root CA private key and its password (if protected) are read from local files, separate from the codebase. The password file is optional; if missing, the key is assumed to be non-protected.
- **Authorization:** Backend access is strictly enforced via the `AdminAuthorizationFilterAttribute`, which checks for the `admin` group claim from Authentik.
- **Data Protection:** ASP.NET Core Data Protection keys MUST be persisted to a volume (e.g., `/app/asp-keys`) in Docker environments to prevent Antiforgery (CSRF) token invalidation after container restarts. Each service (Frontend/Backend) must have an isolated key ring.

### Testing
- **DevTestApp:** A console project used for rapid prototyping and unit-level verification of cryptographic or logic changes.
- **Audit Logs:** All certificate issuance events (Manual and ACME) must be logged to the `AuditLogs` table.
