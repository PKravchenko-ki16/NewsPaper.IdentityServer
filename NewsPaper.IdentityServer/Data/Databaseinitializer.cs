using System;
using System.Security.Claims;
using IdentityModel;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Internal;
using Microsoft.Extensions.DependencyInjection;

namespace NewsPaper.IdentityServer.Data
{
    public static class DatabaseInitializer
    {
        public static void Init(IServiceProvider scopeServiceProvider)
        {
            var userManager = scopeServiceProvider.GetService<UserManager<IdentityUser>>();

            var user = new IdentityUser
            {
                UserName = "IdentityUser"
            };
            var author = new IdentityUser
            {
                UserName = "IdentityAuthor"
            };
            var editor = new IdentityUser
            {
                UserName = "IdentityEditor"
            };

            var resultUser = userManager.CreateAsync(user, "123qwe").GetAwaiter().GetResult();
            var resultAuthor = userManager.CreateAsync(author, "123qwe").GetAwaiter().GetResult();
            var resultEditor = userManager.CreateAsync(editor, "123qwe").GetAwaiter().GetResult();

            if (resultUser.Succeeded && resultAuthor.Succeeded && resultEditor.Succeeded)
            {
                userManager.AddClaimAsync(user, new Claim(ClaimTypes.Role, "User")).GetAwaiter().GetResult();
                userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.Scope, "OrdersAPI")).GetAwaiter().GetResult();
                userManager.AddClaimAsync(author, new Claim(ClaimTypes.Role, "Author")).GetAwaiter().GetResult();
                userManager.AddClaimAsync(author, new Claim(JwtClaimTypes.Scope, "OrdersAPI")).GetAwaiter().GetResult();
                userManager.AddClaimAsync(editor, new Claim(ClaimTypes.Role, "Editor")).GetAwaiter().GetResult();
                userManager.AddClaimAsync(editor, new Claim(JwtClaimTypes.Scope, "OrdersAPI")).GetAwaiter().GetResult();
            }

            scopeServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

            var context = scopeServiceProvider.GetRequiredService<ConfigurationDbContext>();
            context.Database.Migrate();
            if (!context.Clients.Any())
            {
                foreach (var client in IdentityServerConfiguration.GetClients())
                {
                    context.Clients.Add(client.ToEntity());
                }
                context.SaveChanges();
            }

            if (!context.IdentityResources.Any())
            {
                foreach (var resource in IdentityServerConfiguration.GetIdentityResources())
                {
                    context.IdentityResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }

            if (!context.ApiResources.Any())
            {
                foreach (var resource in IdentityServerConfiguration.GetApiResources())
                {
                    context.ApiResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }
        }
    }
}