using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4.Models;
using IdentityServer4.Services;

namespace NewsPaper.IdentityServer.Infrastructure
{
    public class ProfileService : IProfileService
    {
        /// <summary>
        /// This method is called whenever claims about the user are requested (e.g. during token creation or via the userinfo endpoint)
        /// </summary>
        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var claim = context.Subject.Identity as ClaimsIdentity;
            if (claim != null)
            {
                var claimRole = claim.FindFirst(ClaimTypes.Role);
                var claimLogin = claim.FindFirst("name");
                if (claimLogin== null)
                {
                    claimLogin = claim.FindFirst(ClaimTypes.Name);
                }
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Role, claimRole.Value),
                    new Claim(ClaimTypes.Name, claimLogin.Value),
                };

                context.IssuedClaims.AddRange(claims);
            }

            return Task.CompletedTask;
        }

        /// <summary>
        /// This method gets called whenever identity server needs to determine if the user is valid or active (e.g. if the user's account has been deactivated since they logged in).
        /// (e.g. during token issuance or validation).
        /// </summary>
        public Task IsActiveAsync(IsActiveContext context)
        {
            context.IsActive = true;
            return Task.CompletedTask;
        }
    }
}
