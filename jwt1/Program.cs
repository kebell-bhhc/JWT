using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Linq;

namespace jwt1
{
    class Program
    {
        static void Main(string[] args)
        {
            // Simple create and red of a JWT token
            
            // This creates the JWT

            var plainTextSecurityKey = "Life is really simple, but we insist on making it complicated."; //Confucius
            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(plainTextSecurityKey));
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            var securityTokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new List<Claim>()
                    {
                        // These are required for bhhc gateway
                        new Claim(JwtRegisteredClaimNames.Sub, "johndoe"),      // this is the same as ClaimTypes.NameIdentifier 
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),

                        // These are optional other values

                        new Claim(ClaimTypes.NameIdentifier, "johndoe@example.com"),
                        new Claim(ClaimTypes.Role, "Administrator"),
                        new Claim(ClaimTypes.Role, "SuperUser"),
                        new Claim(ClaimTypes.Name, "John Doe"),
                        new Claim("BHHC.GroupID", "4103")
                    }, "Custom"),
                NotBefore = DateTime.Now,
                SigningCredentials = signingCredentials,
                Issuer = "self",
                IssuedAt = DateTime.Now,
                Expires = DateTime.Now.AddHours(3),
                Audience = "http://xbhhcwebapp.bhhc.com",
                
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var plainToken = tokenHandler.CreateToken(securityTokenDescriptor);
            var signedAndEncodedToken = tokenHandler.WriteToken(plainToken);        // The final token to added to cookie or header


            

            //==========================================================================
            //  This reads the JWT on the other side of the call

            //  Validating the token on the server side
            var validationParameters = new TokenValidationParameters()
            {
                ValidateAudience = true,
                ValidAudience = "http://xbhhcwebapp.bhhc.com",
                ValidateIssuer = true,
                ValidIssuer = "self",
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
            try
            {
                SecurityToken outPlainToken = new JwtSecurityToken();
                //var tokenHandler = new JwtSecurityTokenHandler();  // declared above, would be needed if on receiving side of call.
                // validates and creates principal object
                var principal = tokenHandler.ValidateToken(signedAndEncodedToken, validationParameters, out outPlainToken);

                // 1. Read claim under principal with standard type
                var username = principal.Claims.First(c => c.Type == ClaimTypes.Name).Value;

                // 2. Read custom claim value
                int groupId = 0;
                Int32.TryParse(principal.Claims.First(c => c.Type == "BHHC.GroupID").Value, out groupId);

                // 3. Read custom claim value       throws => Message = "Sequence contains no matching element"
                // var wrongClaim = principal.Claims.First(c => c.Type == "NonExistantClaimType").Value;

                // 4. Read from the jwtToken object instead of principal
                var jwtToken = tokenHandler.ReadJwtToken(signedAndEncodedToken);

                // dates are seconds from epoch
                int expirationValue = 0;
                Int32.TryParse(jwtToken.Claims.First(c => c.Type == JwtRegisteredClaimNames.Exp).Value, out expirationValue);
                var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var expirationDate = epoch.AddSeconds(expirationValue);

                // Read all claims from JWT              
                foreach (var claim in principal.Claims)
                {
                    Console.Write(claim.Type + " = ");
                    Console.WriteLine(claim.Value);
                }

            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Authentication failed");
                Console.WriteLine(ex);
            }

            Console.ReadLine();

        }
    }
}
