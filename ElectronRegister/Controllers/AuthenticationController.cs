using ElectronRegister.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace ElectronRegister.Controllers
{
	public class AuthenticationController : Controller
	{
		
		public static User user = new User();
        private readonly IConfiguration _configuration;
		public AuthenticationController(IConfiguration configuration )
        {
            _configuration = configuration;
        }


        [HttpPost("register")]
		public async Task <ActionResult<User>> Register(UserDTO request)
		{
			CreatePasswordHash(request.Password, out byte[] passwordhash, out byte[] passwordsalt);
            user.Username = request.Username;
			user.PasswordHash = passwordhash;
			user.PasswordSalt = passwordsalt;
			return Ok(user);
		}
		[HttpPost("login")]
		public async Task<ActionResult<string>> Login(UserDTO request)
		{
		 if(user.Username!=request.Username)
			{
				return BadRequest("User not found");
			}
		 if(!VerifyPasswordHash(request.Password,user.PasswordHash,user.PasswordSalt)) 
			{
				return BadRequest("Wrong password");
			}
			string token = CreateToken(user);
		 return Ok(token);
			
		}
		private string CreateToken(User user)
		{
			List<Claim> claims = new List<Claim>
	{
		new Claim(ClaimTypes.Name, user.Username),
	};

			// Generate a strong key with the correct length (64 bytes for 512 bits)
			var keyBytes = new byte[64];
			using (var rng = new RNGCryptoServiceProvider())
			{
				rng.GetBytes(keyBytes);
			}
			var key = new SymmetricSecurityKey(keyBytes);

			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

			var token = new JwtSecurityToken(
				claims: claims,
				expires: DateTime.Now.AddDays(1),
				signingCredentials: creds);

			var jwt = new JwtSecurityTokenHandler().WriteToken(token);

			return jwt;
		}
		private void CreatePasswordHash(string password,out byte[] passwordhash,out byte[] passwordsalt) 
		{ 
          using(var hmac = new HMACSHA512()) {

				passwordsalt = hmac.Key;
				passwordhash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
			}
		}
		private bool VerifyPasswordHash(string password, byte[] passwordhash, byte[] passwordsalt)
		{
			using (var hmac = new HMACSHA512(passwordsalt))
			{
				var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
				return computeHash.SequenceEqual(passwordhash);

			}
		}
		
	}
}
