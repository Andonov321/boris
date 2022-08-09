using ConsulteerProject;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace ConsulteerWebApiProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {

        public static User user = new User();
        private readonly IConfiguration configuration;

        public UserController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        //List with random users
        private static List<UserDto> users = new List<UserDto>
            {
                new UserDto {
                 UserName = "Boris",
                 Password = "password123"
                },

                new UserDto {
                 UserName = "Marko",
                 Password = "password321"
                }
            };

        //List for logged user
        private static List<UserDto> loggedUser = new List<UserDto>();

        //Registration of user and adding in list of users
        [HttpPost("Register"), AllowAnonymous]
        public async Task<ActionResult<User>> Register(UserDto request)
        {

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            users.Add(request);

            return Ok(user);

        }

        //Login of user and adding user in list of logged users
        [HttpPost("Login"), AllowAnonymous]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (user.Username != request.UserName)
            {
                return BadRequest("User not found!");
            }

            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password!");
            }

            string token = CreateToken(user);

            loggedUser.Add(request);

            return Ok(token);
        }


        //Get list of all users
        [HttpGet("List of users"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<List<UserDto>>> Get()
        {
            return Ok(users);
        }

        //Get user by their username
        [HttpGet("User by {username}"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<UserDto>> Get(string username)
        {

            var user = users.Find(h => h.UserName == username);
            if (user == null)
                return BadRequest("User not found!");

            return Ok(user);
        }

        //Get logged in user
        [HttpGet("Logged User"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<UserDto>> GetLoggedUser()
        {
            return Ok(loggedUser);
        }


        //Add new user
        [HttpPost("New user"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<List<UserDto>>> AddUser(UserDto user)
        {

            users.Add(user);

            return Ok(users);

        }

        //Change information of user
        [HttpPut("Update user"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<List<UserDto>>> UpdateUser(UserDto username)
        {
            var user = users.Find(h => h.UserName == username.UserName);
            if (user == null)
                return BadRequest("User not found!");

            user.UserName = username.UserName;
            user.Password = username.Password;

            return Ok(users);

        }

        //Delete user 
        [HttpDelete("Delete user by {username}"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<List<UserDto>>> Delete(string username)
        {

            var user = users.Find(h => h.UserName == username);
            if (user == null)
                return BadRequest("User not found!");

            users.Remove(user);
            return Ok(users);
        }

        //Method for creating token
        private string CreateToken(User user)
        {

            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(configuration.GetSection(
                "AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;

        }


        //Method for creating PasswordHash
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {

            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }

        }


        //Method for verifying password hash
        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {

            using (var hmac = new HMACSHA512(user.PasswordSalt))
            {

                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);

            }

        }

    }
}
