using DAL;
using DAL.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using System;

namespace Backend
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var host = CreateHostBuilder(args).Build();

            using (var scope = host.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                try
                {
                    Log.Information("Applying Backend migrations...");
                    
                    var db = services.GetRequiredService<DB>();
                    db.Database.Migrate();

                    var identityDb = services.GetRequiredService<IdentityDBContext>();
                    identityDb.Database.Migrate();
                    
                    Log.Information("Backend migrations applied successfully.");
                }
                catch (Exception ex)
                {
                    Log.Fatal(ex, "An error occurred while migrating the database.");
                }
            }

            host.Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
