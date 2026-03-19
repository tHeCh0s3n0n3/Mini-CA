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

namespace Backend.Services;

public class AcmeAccountService : IAccountService
{
    private readonly DB _db;
    private readonly IConfiguration _configuration;

    public AcmeAccountService(DB db, IConfiguration configuration)
    {
        _db = db;
        _configuration = configuration;
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
        var dbAccount = new AcmeAccount
        {
            AccountKey = ComputeThumbprint(jwk),
            CreatedAt = DateTime.UtcNow
        };

        _db.AcmeAccounts.Add(dbAccount);
        await _db.SaveChangesAsync(cancellationToken);

        var account = new OpenCertServer.Acme.Abstractions.Model.Account(jwk, contact, termsOfServiceAgreed ? DateTimeOffset.UtcNow : null);
        SetAccountId(account, dbAccount.Id.ToString());
        account.Status = AccountStatus.Valid;
        
        return account;
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
        return (await LoadAccount(accountId, cancellationToken))!;
    }
}
