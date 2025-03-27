using BlackVeilAPI.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MySql.Data.MySqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace BlackVeilAPI.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly DatabaseHelper _dbHelper;
        public AuthController(IConfiguration configuration)
        {
            _dbHelper = new DatabaseHelper(configuration.GetConnectionString("DefaultConnection"));
        }
        //POST: új fiók regisztrálása - public
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!IsValidEmail(request.Email))
            {
                return BadRequest(new { message = "Hibás email formátum!" });
            }

            if (!IsValidPassword(request.Password))
            {
                return BadRequest(new { message = "A jelszónak tartalmaznia kell legalább egy nagybetűt, egy számot, és 8-15 karakter hosszúnak kell lennie!" });
            }

            const string checkEmailQuery = "SELECT COUNT(*) FROM Users WHERE Email = @Email";
            var checkEmailParams = new MySqlParameter("@Email", request.Email);
            var emailCount = Convert.ToInt32(await _dbHelper.ExecuteScalarAsync<int>(checkEmailQuery, new[] { checkEmailParams }));

            if (emailCount > 0)
            {
                return Conflict(new { message = "Ez az emailcím már foglalt!" });
            }

            const string insertQuery = "INSERT INTO Users (Username, Email, Password) VALUES (@Username, @Email, @Password)";
            var parameters = new MySqlParameter[] {
                new MySqlParameter("@Username", request.Username),
                new MySqlParameter("@Email", request.Email),
                new MySqlParameter("@Password", BCrypt.Net.BCrypt.HashPassword(request.Password)),
            };

            await _dbHelper.ExecuteNonQueryAsync(insertQuery, parameters);

            return Ok(new { message = "Sikeres regisztráció!" });
        }
        //POST: bejelentkezés meglévő fiókkal - public
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            const string query = "SELECT userId, Password FROM Users WHERE Email = @Email";
            var parameters = new MySqlParameter[] { new MySqlParameter("@Email", request.Email) };
            var result = await _dbHelper.ExecuteQueryAsync(query, parameters);

            if (result.Rows.Count == 0)
                return Unauthorized(new { message = "Hibás felhasználónév vagy jelszó!" });

            var row = result.Rows[0];
            var userId = Convert.ToInt32(row["userId"]);
            var passwordHash = row["Password"].ToString();


            if (!BCrypt.Net.BCrypt.Verify(request.Password, passwordHash))
                return Unauthorized(new { message = "Hibás felhasználónév vagy jelszó!" });

            var token = GenerateJwtToken(userId);

            return Ok(new { token });
        }
        //POST: kijelentkezés - public
        [HttpPost("logout")]
        public IActionResult Logout()
        {
            return Ok(new { message = "Sikeres kijelentkezés!" });
        }

        private string GenerateJwtToken(int userId)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("e96e265f7322b7478456784568re5d9cf873c13e13db30cc85"));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);


            var token = new JwtSecurityToken(
                issuer: "BlackVeil",
                audience: "BlackVeilUser",
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private bool IsValidEmail(string email)
        {
            var pattern = @"^[\w\.-]+@[a-zA-Z\d-]+\.[a-zA-Z]{2,}$";
            return Regex.IsMatch(email, pattern);
        }

        private bool IsValidPassword(string password)
        {
            var pattern = @"^(?=.*[A-Z])(?=.*\d).{8,15}$";
            return Regex.IsMatch(password, pattern);
        }
    }
    public class LoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
    public class RegisterRequest
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
