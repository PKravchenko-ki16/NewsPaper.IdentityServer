using System.Collections.Generic;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;

namespace NewsPaper.IdentityServer
{
    public static class IdentityServerConfiguration
    {
        public static IEnumerable<Client> GetClients() =>
        new List<Client>
        {
            new Client
            {
                ClientId = "client_id",
                ClientSecrets = { new Secret("client_secret".ToSha256()) },
                
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                AllowedScopes =
                {
                    "GatewayClientApi",
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile
                }
            },
            new Client
            {
                ClientId = "client_id_mvc",
                ClientSecrets = { new Secret("client_secret_mvc".ToSha256()) },

                AllowedGrantTypes = GrantTypes.Code,

                AllowedScopes =
                {
                    "OrdersAPI",
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile
                },

                RedirectUris = {"https://localhost:2001/signin-oidc"},
                PostLogoutRedirectUris = {"https://localhost:2001/signout-callback-oidc"},

                RequireConsent = false,

                AlwaysIncludeUserClaimsInIdToken = true,

                AccessTokenLifetime = 30,

                AllowOfflineAccess = true
            }
        };
      
        public static IEnumerable<ApiResource> GetApiResources()
        {
            yield return new ApiResource("SwaggerAPI");
            yield return new ApiResource("GatewayClientApi");
            yield return new ApiResource("OrdersAPI");
        }

        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            yield return new IdentityResources.OpenId();
            yield return new IdentityResources.Profile();
        }

        public static IEnumerable<ApiScope> GetApiScopes()
        {
            yield return new ApiScope("SwaggerAPI", "Swagger API");
            yield return new ApiScope("OrdersAPI", "Orders API");
            yield return new ApiScope("GatewayClientApi", "Gateway Client Api");
        }
    }
}
