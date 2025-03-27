using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using MySql.Data.MySqlClient;
using BlackVeilAPI.Utils;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
            ValidAudience = builder.Configuration["JwtSettings:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JwtSettings:Key"]))
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<DatabaseHelper>(sp =>
    new DatabaseHelper(builder.Configuration.GetConnectionString("ApplicationConnection")));
var app = builder.Build();
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
try
{
    using (var connection = new MySqlConnection(connectionString))
    {
        await connection.OpenAsync();

        string dbName = "blackveildb";
        var createDbCommand = new MySqlCommand(
            $"CREATE DATABASE IF NOT EXISTS {dbName} CHARACTER SET utf8 COLLATE utf8_hungarian_ci",
            connection
        );
        await createDbCommand.ExecuteNonQueryAsync();

        await connection.ChangeDatabaseAsync(dbName);

        var checkTableCommand = new MySqlCommand("SHOW TABLES LIKE 'Users'", connection);
        var tableExists = (await checkTableCommand.ExecuteScalarAsync()) != null;

        if (!tableExists)
        {
            var sqlScriptPath = Path.Combine(
                Directory.GetCurrentDirectory(),
                "Scripts",
                "schema.sql"
            );

            var sqlScript = await File.ReadAllTextAsync(sqlScriptPath);

            sqlScript = $"USE {dbName};\n" + sqlScript;

            var statements = sqlScript.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var statement in statements)
            {
                var trimmedStatement = statement.Trim();
                if (!string.IsNullOrEmpty(trimmedStatement))
                {
                    using (var cmd = new MySqlCommand(trimmedStatement, connection))
                    {
                        await cmd.ExecuteNonQueryAsync();
                    }
                }
            }
            Console.WriteLine("Adatbázis sikeresen létrehozva.");
        }
    }
}
catch (Exception ex)
{
    Console.WriteLine($"An error occurred during database initialization: {ex.Message}");
}


if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors("AllowAll");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
