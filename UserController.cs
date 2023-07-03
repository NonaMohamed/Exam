using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using UserAPIApplication.DTOs;
using UserAPIApplication.Models;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

namespace UserAPIApplication.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
    
      private readonly UserContext _context;

         
       public UserController(UserContext context)
            {
                _context = context;
            }

            [HttpPost]
            public ActionResult<UserDTO> CreateUser(UserDTO userDto)
            {
                var id = GenerateId(userDto.Id);
                var accessToken = GenerateAccessToken();

                var user = new User
                {
                    Id = id,
                    FirstName = userDto.FirstName,
                    LastName = userDto.LastName,
                     Email = userDto.Email,
                    MarketingConsent = userDto.MarketingConsent
                };

                _context.Users.Add(user);
                _context.SaveChanges();

                var response = new UserDTO
                {
                    Id = id,
                    FirstName = userDto.FirstName,
                    LastName = userDto.LastName,
                    MarketingConsent = userDto.MarketingConsent
                };

                return Ok(response);
            }

            [HttpGet("{id}")]
            public ActionResult<UserDTO> GetUser(string id, string accessToken)
            {
                var user = _context.Users.FirstOrDefault(u => u.Id == id);

                if (user == null)
                {
                    return NotFound();
                }

                if (accessToken != GenerateAccessToken())
                {
                    return Unauthorized();
                }

                var response = new UserDTO
                {
                    Id = id,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    MarketingConsent = user.MarketingConsent
                };

                if (!user.MarketingConsent)
                {
                    response.Email = null;
                }

                return Ok(response);
            }

            private string GenerateId(string email)
            {
                var sha1 = System.Security.Cryptography.SHA1.Create();
                var salt = "450d0b0db2bcf4adde5032eca1a7c416e560cf44";
                var hashedEmail = sha1.ComputeHash(System.Text.Encoding.UTF8.GetBytes(email + salt));
                return BitConverter.ToString(hashedEmail).Replace("-", "").ToLower();
            }

        private string GenerateAccessToken()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("mysecretkey1234567890");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())
        }),
                Expires = DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
