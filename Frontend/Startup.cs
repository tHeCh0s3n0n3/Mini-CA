using DAL;
using DAL.Identity;
using DAL.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Serilog;
using Microsoft.AspNetCore.DataProtection;
using System.IO;

namespace Frontend;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Verbose()
            .WriteTo.File("/app/logs/Log.txt")
            .CreateLogger();
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo("/app/asp-keys/frontend/"))
            .SetApplicationName("MiniCA-Frontend");

        services.AddDbContext<DB>(options =>
            options.ReplaceService<IValueConverterSelector
                                   , StronglyTypedIdValueConverterSelector>()
                   .UseSqlite(Configuration.GetConnectionString("SQLiteConnection"))
        );
        services.AddDbContext<IdentityDBContext>(options =>
            options.UseSqlite(
                Configuration.GetConnectionString("IdentityConnection")));
        services.AddDatabaseDeveloperPageExceptionFilter();

        services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false)
            .AddEntityFrameworkStores<IdentityDBContext>();

        services.AddAuthentication(o =>
        {
            o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
            .AddCookie(options =>
            {
                options.Cookie.Name = "MiniCA.Frontend.Auth";
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

                o.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    NameClaimType = "preferred_username"
                };
            });

        services.AddControllersWithViews();
        services.AddRazorPages()
                .AddRazorRuntimeCompilation();
        services.AddHealthChecks();
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app
                          , IWebHostEnvironment env
                          , ILoggerFactory loggerFactory)
    {
        loggerFactory.AddSerilog();

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
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }
        app.UseHttpsRedirection();
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
