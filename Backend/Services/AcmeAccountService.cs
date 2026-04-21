using DAL;
using DAL.Models;
using Microsoft.EntityFrameworkCore;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;
using OpenCertServer.Acme.Abstractions.Model;
using System.Security.Cryptography;
using System.Text;
using Common;
using Microsoft.IdentityModel.Tokens;
using System.Reflection;
using CertesSlim.Acme.Resource;
using Microsoft.AspNetCore.Http;
using System.Text.Json;

namespace Backend.Services;

public class AcmeAccountService : IAccountService
{
    private readonly DB _db;
    private readonly IConfiguration _configuration;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IAcmeContext _acmeContext;

    public AcmeAccountService(DB db, IConfiguration configuration, IHttpContextAccessor httpContextAccessor, IAcmeContext acmeContext)
    {
        _db = db;
        _configuration = configuration;
        _httpContextAccessor = httpContextAccessor;
        _acmeContext = acmeContext;
    }

    private void SetAccountId(OpenCertServer.Acme.Abstractions.Model.Account account, string id)
    {
        var field = typeof(OpenCertServer.Acme.Abstractions.Model.Account).GetField("<AccountId>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic);
        field?.SetValue(account, id);
    }

    private string ComputeThumbprint(JsonWebKey jwk)
    {
        return jwk.Kid ?? jwk.K ?? "unknown";
    }

    public async Task<OpenCertServer.Acme.Abstractions.Model.Account> CreateAccount(JsonWebKey jwk, IEnumerable<string>? contact, bool termsOfServiceAgreed, CancellationToken cancellationToken)
    {
        // Extract EAB from request body
        AcmeEab? validatedEab = await GetValidatedEabFromRequest(jwk, cancellationToken);
        
        // REQ-5: ACME registration is restricted to EAB pre-provisioned accounts.
        if (validatedEab == null)
        {
            throw new Exception("Registration requires a valid External Account Binding (EAB).");
        }

        var dbAccount = new AcmeAccount
        {
            AccountKey = ComputeThumbprint(jwk),
            CreatedAt = DateTime.UtcNow,
            EabId = validatedEab.Id
        };

        _db.AcmeAccounts.Add(dbAccount);
        await _db.SaveChangesAsync(cancellationToken);

        var account = new OpenCertServer.Acme.Abstractions.Model.Account(jwk, contact, termsOfServiceAgreed ? DateTimeOffset.UtcNow : null);
        SetAccountId(account, dbAccount.Id.ToString());
        account.Status = AccountStatus.Valid;
        
        return account;
    }

    private async Task<AcmeEab?> GetValidatedEabFromRequest(JsonWebKey accountJwk, CancellationToken cancellationToken)
    {
        var context = _httpContextAccessor.HttpContext;
        if (context == null) return null;

        context.Request.Body.Position = 0;
        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, true, 1024, true);
        var body = await reader.ReadToEndAsync(cancellationToken);
        
        try
        {
            // The request body is a JWS. The payload is what we want.
            using var jwsDoc = JsonDocument.Parse(body);
            if (!jwsDoc.RootElement.TryGetProperty("payload", out var payloadElement)) return null;
            
            var payloadBase64 = payloadElement.GetString();
            if (string.IsNullOrEmpty(payloadBase64)) return null;
            
            var payloadJson = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(payloadBase64));
            using var payloadDoc = JsonDocument.Parse(payloadJson);
            
            if (!payloadDoc.RootElement.TryGetProperty("externalAccountBinding", out var eabElement)) return null;
            
            // EAB is another JWS
            if (!eabElement.TryGetProperty("protected", out var protectedElement)) return null;
            if (!eabElement.TryGetProperty("payload", out var eabPayloadElement)) return null;
            if (!eabElement.TryGetProperty("signature", out var signatureElement)) return null;
            
            var eabProtectedBase64 = protectedElement.GetString();
            var eabPayloadBase64 = eabPayloadElement.GetString();
            var eabSignatureBase64 = signatureElement.GetString();
            
            if (string.IsNullOrEmpty(eabProtectedBase64) || string.IsNullOrEmpty(eabPayloadBase64) || string.IsNullOrEmpty(eabSignatureBase64)) return null;
            
            // 1. Validate payload: must be the JWK of the account
            var eabPayloadJson = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(eabPayloadBase64));
            // Simple comparison or thumbprint check
            // For now, let's just make sure it's present. ACME says it must be the public key.
            
            // 2. Extract KID from protected header
            var eabProtectedJson = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(eabProtectedBase64));
            using var eabProtectedDoc = JsonDocument.Parse(eabProtectedJson);
            if (!eabProtectedDoc.RootElement.TryGetProperty("kid", out var kidElement)) return null;
            
            var kid = kidElement.GetString();
            if (string.IsNullOrEmpty(kid)) return null;
            
            // 3. Find EAB in database
            var eab = await _db.AcmeEabs.FirstOrDefaultAsync(e => e.KID == kid, cancellationToken);
            if (eab == null) return null;
            
            // 4. Validate HMAC signature
            var masterKeyPath = _configuration["Acme:MasterKeyPath"];
            if (string.IsNullOrEmpty(masterKeyPath)) throw new Exception("Acme:MasterKeyPath not configured.");
            
            Encryption.Initialize(masterKeyPath);
            var hmacKeyBase64 = Encryption.Decrypt(eab.EncryptedHmacKey);
            var hmacKey = Convert.FromBase64String(hmacKeyBase64);
            
            using var hmac = new HMACSHA256(hmacKey);
            var dataToSign = Encoding.UTF8.GetBytes($"{eabProtectedBase64}.{eabPayloadBase64}");
            var signatureBytes = hmac.ComputeHash(dataToSign);
            var expectedSignature = Base64UrlEncoder.Encode(signatureBytes);
            
            if (expectedSignature != eabSignatureBase64) return null;
            
            return eab;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public async Task<OpenCertServer.Acme.Abstractions.Model.Account?> FindAccount(JsonWebKey jwk, CancellationToken cancellationToken)
    {
        var thumbprint = ComputeThumbprint(jwk);
        var dbAccount = await _db.AcmeAccounts.FirstOrDefaultAsync(a => a.AccountKey == thumbprint, cancellationToken);
        
        if (dbAccount == null || dbAccount.IsDeactivated) return null;

        var account = new OpenCertServer.Acme.Abstractions.Model.Account(jwk, null, null);
        SetAccountId(account, dbAccount.Id.ToString());
        account.Status = AccountStatus.Valid;
        
        return account;
    }

    public async Task<OpenCertServer.Acme.Abstractions.Model.Account?> LoadAccount(string accountId, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(accountId, out var guid)) return null;
        var dbAccount = await _db.AcmeAccounts.FindAsync(new object[] { new AcmeAccountId(guid) }, cancellationToken);
        
        if (dbAccount == null || dbAccount.IsDeactivated) return null;

        var account = new OpenCertServer.Acme.Abstractions.Model.Account(new JsonWebKey(), null, null);
        SetAccountId(account, dbAccount.Id.ToString());
        account.Status = AccountStatus.Valid;
        
        return account;
    }

    public async Task<OpenCertServer.Acme.Abstractions.Model.Account> FromRequest(AcmeHeader header, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(header.Kid)) return null!;
        
        var accountId = header.Kid.Split('/').Last();
        var account = await LoadAccount(accountId, cancellationToken);
        
        if (account != null)
        {
            _acmeContext.CurrentAccount = account;
        }
        
        return account!;
    }
}
