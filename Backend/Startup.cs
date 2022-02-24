using Common;
using DAL;
using DAL.Identity;
using DAL.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Backend
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
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
                o.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
                .AddCookie()
                .AddNextcloud(o =>
                {
                    o.ClientId = Configuration["Nextcloud:ClientID"];
                    o.ClientSecret = Configuration["Nextcloud:Secret"];

                    o.AuthorizationEndpoint = Configuration["Nextcloud:BaseUrl"]
                                              + NextcloudIdentityProviderDefaults.AuthorizationEndpointPath;
                    o.TokenEndpoint = Configuration["Nextcloud:BaseUrl"]
                                      + NextcloudIdentityProviderDefaults.TokenEndpointPath;
                    o.UserInformationEndpoint = Configuration["Nextcloud:BaseUrl"]
                                                + NextcloudIdentityProviderDefaults.UserInformationEndpointPath;

                    //o.ClaimActions.MapJsonKey("urn:nextcloud:displayname", "Name", "string");
                    o.ClaimActions.MapJsonKey("Name", "urn:nextcloud:displayname", "string");
                    o.SaveTokens = true;
                });

            services.Configure<Models.CACertSettings>(Configuration.GetSection("CACert"));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
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
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }
    }
}
