using ASPDotNetCRUDApp.Configurations;
using ASPDotNetCRUDApp.DTOs;
using ASPDotNetCRUDApp.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ASPDotNetCRUDApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        //IdentityUser is the default user
        private readonly UserManager<IdentityUser> _userManager;
        //private readonly JwtConfig _jwtConfig;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
           _configuration = configuration;
            _userManager = userManager;
        }

        [HttpPost]
        [Route("Register")]

        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDTO requestDTO)
        {
            //validate the incoming request
            if(ModelState.IsValid)
            {
                //We need to check if the email already exists

                var user_exist = await _userManager.FindByEmailAsync(requestDTO.Email); 
                if (user_exist != null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Email already exists"
                        }

                    });
                }
                // create a user
                var new_user = new IdentityUser()
                {
                    Email= requestDTO.Email,
                    UserName=requestDTO.Email
                };

                var is_created = await _userManager.CreateAsync(new_user,requestDTO.Password);

                if (is_created.Succeeded)
                {
                    var token = GenerateJwtToken(new_user);
                    return Ok(new AuthResult()
                    {
                        Result = true,
                        Token= token
                    });
                }
                return BadRequest(new AuthResult()
                {
                    Result= false, 
                    Errors = new List<string>()
                    {
                        string.Join(",",is_created.Errors.Select(err => err.Description))
                    }
                });
            }
            return BadRequest("Server Error");
        }


        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDTO loginRequest)
        {
            if(ModelState.IsValid)
            {
                //check whether the user exists

                var existing_user = await _userManager.FindByEmailAsync(loginRequest.Email);    
                if(existing_user == null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Errors= new List<string>()
                        {
                            "Invalid Payload"
                        },
                        Result = false
                    });
                }

                var isCorrect = await _userManager.CheckPasswordAsync(existing_user,loginRequest.Password);
                if (!isCorrect)
                {
                    return BadRequest(new AuthResult()
                    {
                        Errors = new List<string>()
                        {
                            "Invalid Credentials"
                        },
                        Result = false
                    });
                }

                var jwtToken = GenerateJwtToken(existing_user);
                return Ok(new AuthResult()
                {
                    Token = jwtToken,
                    Result= true
                });

            }
            return BadRequest(new AuthResult()
            {
                Errors = new List<string>()
                {
                    "Invalid Payload"
                },
                Result=false
            });
        }

        private string GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.UTF8.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value);

            //Token Descriptor

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("Id",user.Id),
                    new Claim(JwtRegisteredClaimNames.Sub,user.Email),
                    new Claim(JwtRegisteredClaimNames.Email,user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
                }),
                Expires = DateTime.Now.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            return jwtToken;
        }
    }
}
