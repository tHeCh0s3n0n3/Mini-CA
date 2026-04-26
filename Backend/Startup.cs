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

namespace Backend;

public class Startup
{
    public IConfiguration Configuration { get; }

    public Startup(IConfiguration configuration)
    {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Verbose()
            .WriteTo.File("/app/logs/Log.txt")
            .CreateLogger();
        Configuration = configuration;
    }

    public void ConfigureServices(IServiceCollection services)
    {
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

        services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
            .AddEntityFrameworkStores<IdentityDBContext>();
        services.AddControllersWithViews();

        services.AddAuthentication(o =>
        {
            o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
            .AddCookie()
            .AddOpenIdConnect(o =>
            {
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

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILoggerFactory loggerFactory)
    {
        loggerFactory.AddSerilog();

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
        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
        };
        forwardedHeadersOptions.KnownNetworks.Clear();
        forwardedHeadersOptions.KnownProxies.Clear();
        app.UseForwardedHeaders(forwardedHeadersOptions);
        
        app.Use((context, next) =>
        {
            context.Request.EnableBuffering();
            return next();
        });

        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        // ACME Middleware
        app.UseAcmeServer();

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
