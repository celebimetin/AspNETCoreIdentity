using IdentityWebApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityWebApp.ClaimProvider
{
    public class ClaimProvider : IClaimsTransformation
    {
        public UserManager<AppUser> UserManager { get; set; }

        public ClaimProvider(UserManager<AppUser> userManager)
        {
            UserManager = userManager;
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            if (principal != null && principal.Identity.IsAuthenticated)
            {
                var identity = principal.Identity as ClaimsIdentity;
                var user = await UserManager.FindByNameAsync(identity.Name);
                if (user != null)
                {
                    if (user.City != null)
                    {
                        if (!principal.HasClaim(c => c.Type == "city"))
                        {
                            Claim claimCity = new Claim("city", user.City, ClaimValueTypes.String, "Internal");
                            identity.AddClaim(claimCity);
                        }
                    }
                }
            }
            return principal;
        }
    }
}