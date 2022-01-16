using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace DAL.Identity;
public class IdentityDBContext : IdentityDbContext
{
    public IdentityDBContext(DbContextOptions<IdentityDBContext> options)
        : base(options)
    {
    }
}

/// <summary>
/// For use by dotnet-ef for migrations
/// </summary>
public class IdentityDBContextFactory : IDesignTimeDbContextFactory<IdentityDBContext>
{
    public IdentityDBContext CreateDbContext(string[] args)
    {
        DbContextOptionsBuilder<IdentityDBContext> optionsBuilder = new();
        optionsBuilder.UseSqlite("Data Source=C:\\Users\\Tarek\\Nextcloud\\Development\\Mini CA\\Source Code\\Mini CA\\identity.sqlite");

        return new IdentityDBContext(optionsBuilder.Options);
    }
}