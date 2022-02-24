using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using DAL.Models;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace DAL;

public class DB : DbContext
{
    public DB(DbContextOptions<DB> options)
        : base(options)
    { }

    protected override void OnConfiguring (DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.ReplaceService<IValueConverterSelector
                                       , StronglyTypedIdValueConverterSelector>();
        base.OnConfiguring (optionsBuilder);
    }
        
    public DbSet<CSR> CSRs { get; set; }
    public DbSet<SignedCSR> SignedCSRs { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var conv = typeof(CSRId).GetNestedType("EfCoreValueConverter");

        modelBuilder.Entity<CSR>(entity => {

            entity.ToTable("CSRs");

            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id)
                  .IsRequired();
            entity.Property(e => e.CountryCode)
                  .HasMaxLength(2)
                  .IsFixedLength()
                  .IsRequired();
            entity.Property(e => e.Organization);
            entity.Property(e => e.OrganizationUnitName);
            entity.Property(e => e.CommonName)
                  .IsRequired();
            entity.Property(e => e.AlternateNames);
            entity.Property(e => e.Locality);
            entity.Property(e => e.State);
            entity.Property(e => e.EMailAddress);
            entity.Property(e => e.FileContents)
                  .IsRequired();
            entity.Property(e => e.FileName)
                  .IsRequired();
            entity.Property(e => e.IsSigned);
            entity.Property(e => e.SubmittedOn)
                  .ValueGeneratedOnAdd()
                  .IsRequired();
        });

        modelBuilder.Entity<SignedCSR>(entity =>
        {
            entity.HasKey(e => e.Id);

            entity.Property(e => e.Id)
                  .IsRequired();
            entity.Property(e => e.OriginalRequestId)
                  .IsRequired();
            entity.Property(e => e.SignedOn)
                  .ValueGeneratedOnAdd()
                  .IsRequired();
            entity.Property(e => e.Certificate)
                  .IsRequired();
            entity.Property(e => e.NotBefore)
                  .IsRequired();
            entity.Property(e => e.NotAfter)
                  .IsRequired();
        });
    }
}

/// <summary>
/// For use by dotnet-df for migrations
/// </summary>
public class DBContextFactory : IDesignTimeDbContextFactory<DB>
{
    public DB CreateDbContext(string[] args)
    {
        DbContextOptionsBuilder<DB> optionsBuilder = new();
        optionsBuilder
            .ReplaceService<IValueConverterSelector
                            , StronglyTypedIdValueConverterSelector>()
            .UseSqlite("Data Source=C:\\Users\\Tarek\\Nextcloud\\Development\\Mini CA\\Source Code\\Mini CA\\db.sqlite");

        return new DB(optionsBuilder.Options);
    }
}
