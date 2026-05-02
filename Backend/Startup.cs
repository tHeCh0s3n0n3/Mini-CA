using Common;
using DAL;
using DAL.Identity;
using DAL.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Backend.Services;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Server;
using Serilog;

using Microsoft.AspNetCore.DataProtection;
using System.IO;

namespace Backend;

public class Startup
{
    public IConfiguration Configuration { get; }

    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
        const string outputTemplate = "[{Timestamp:HH:mm:ss} {Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}";

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Verbose()
            .WriteTo.Console(outputTemplate: outputTemplate)
            .WriteTo.File("/app/logs/Log.txt", rollingInterval: RollingInterval.Day, outputTemplate: outputTemplate)
            .ReadFrom.Configuration(Configuration)
            .CreateLogger();

        // Robust Master Key Discovery
        string? masterKeyPath = Configuration["Acme:MasterKeyPath"];
        
        if (string.IsNullOrEmpty(masterKeyPath))
        {
            Log.Information("Acme:MasterKeyPath not found in configuration. Trying default paths...");
            
            string[] searchPaths = ["/app/secrets/master.key"];
            foreach (var path in searchPaths)
            {
                if (File.Exists(path))
                {
                    masterKeyPath = path;
                    Log.Information("Discovered master key at {Path}", path);
                    break;
                }
            }
        }

        if (string.IsNullOrEmpty(masterKeyPath))
        {
            Log.Error("Master key could not be located via configuration or default paths.");
            throw new Exception("Acme:MasterKeyPath is not configured and no file was found at standard locations. Please check your volume mappings.");
        }

        if (!File.Exists(masterKeyPath))
        {
            Log.Error("Master key file path was configured but file does not exist at {Path}", masterKeyPath);
            throw new FileNotFoundException($"Master key file not found at {masterKeyPath}. Ensure the volume is correctly mapped.");
        }

        Encryption.Initialize(masterKeyPath);
    }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo("/app/asp-keys/"))
            .SetApplicationName("MiniCA-Backend");

        services.AddDbContext<DB>(options =>
            options.ReplaceService<IValueConverterSelector
                                   , StronglyTypedIdValueConverterSelector>()
                   .UseSqlite(Configuration.GetConnectionString("SQLiteConnection"))
        );

        services.AddDbContext<IdentityDBContext>(options =>
            options.UseSqlite(
                Configuration.GetConnectionString("IdentityConnection"))
        );
        services.AddDatabaseDeveloperPageExceptionFilter();

        services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false)
            .AddEntityFrameworkStores<IdentityDBContext>();
        services.AddControllersWithViews();

        services.AddAuthentication(o =>
        {
            o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
            .AddCookie(options =>
            {
                options.Cookie.Name = "MiniCA.Backend.Auth";
                options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
                options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
            })
            .AddOpenIdConnect(o =>
            {
                o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.Authority = Configuration["Authentik:Authority"];
                o.ClientId = Configuration["Authentik:ClientId"];
                o.ClientSecret = Configuration["Authentik:ClientSecret"];
                o.ResponseType = "code";
                o.SaveTokens = true;
                o.GetClaimsFromUserInfoEndpoint = true;
                o.Scope.Add("openid");
                o.Scope.Add("profile");
                o.Scope.Add("email");
                o.Scope.Add("groups");

                o.ClaimActions.MapJsonKey("groups", "groups");

                o.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    NameClaimType = "preferred_username",
                    RoleClaimType = "groups"
                };
            });

        // ACME Server Configuration
        services.AddAcmeServer(Configuration);
        services.AddAcmeInMemoryStore();
        
        // Custom ACME Services
        services.AddScoped<IAccountService, AcmeAccountService>();
        services.AddScoped<IIssueCertificates, AcmeIssuanceService>();
        services.AddScoped<IAcmeContext, AcmeContext>();
        services.AddHttpContextAccessor();
        
        services.AddMemoryCache();

        services.Configure<Models.CACertSettings>(Configuration.GetSection("CACert"));

        services.AddHealthChecks();
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
        };
        forwardedHeadersOptions.KnownIPNetworks.Clear();
        forwardedHeadersOptions.KnownProxies.Clear();
        app.UseForwardedHeaders(forwardedHeadersOptions);

        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseMigrationsEndPoint();
        }
        else
        {
            app.UseExceptionHandler("/Home/Error");
            app.UseHsts();
        }
        app.UseHttpsRedirection();
        
        app.Use((context, next) =>
        {
            context.Request.EnableBuffering();
            return next();
        });

        // ACME Middleware
        app.UseAcmeServer();

        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapHealthChecks("/health");
            endpoints.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");
            endpoints.MapRazorPages();
        });
    }
}
