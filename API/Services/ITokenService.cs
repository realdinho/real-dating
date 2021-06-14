using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Entities;
using API.interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace API.Services
{
     public class TokenService : ITokenService
     {
          private readonly SymmetricSecurityKey _key;
          public TokenService(IConfiguration config)
          {
               _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["TokenKey"]));
          }

          string ITokenService.CreateToken(AppUser user)
          {
               // create claims
               var claims = new List<Claim>
               {
                    new Claim(JwtRegisteredClaimNames.NameId, user.UserName)
               };

               // create credentials 
               var credentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

               // describe how the token is going to look
               var tokenDescriptor = new SecurityTokenDescriptor
               {
                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.Now.AddDays(7),
                    SigningCredentials = credentials
               };

               // create token using the token handler
               var tokenHandler = new JwtSecurityTokenHandler();
               var token = tokenHandler.CreateToken(tokenDescriptor);

               return tokenHandler.WriteToken(token); // return token to the user
          }
     }
}