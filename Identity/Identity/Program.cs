
using Identity.Context;
using Identity.Entities;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Identity.Interfaces;
using Lawyer.Application.Services;
using Microsoft.EntityFrameworkCore;

namespace Identity
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.




            // DATABASE 
            builder.Services.AddDbContext<SystemDbContext>(options =>
            {
                options.UseSqlServer(builder.Configuration.GetConnectionString("DatabaseLocal")); // Configura��o do banco de dados 
            });

            // Configura��o do banco de dados com usu�rios e fun��es
            builder.Services.AddIdentity<User, IdentityRole>(options =>
            {
                // Configura��es de normaliza��o
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "; // Adicione ou remova caracteres conforme necess�rio
                options.User.RequireUniqueEmail = true; // Garante que os emails sejam �nicos
            }).AddEntityFrameworkStores<SystemDbContext>()
            .AddDefaultTokenProviders();


            // Configura��o JWT
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                var secretKey = builder.Configuration["TokenSettings:SecretKey"] ?? throw new ArgumentException("Invalid Secret key");

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidAudience = builder.Configuration["TokenSettings:ValidAudience"],
                    ValidIssuer = builder.Configuration["TokenSettings:ValidIssuer"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
                };
            });

            // Configura��o e cria��o de pol�ticas de acesso
            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
                options.AddPolicy("ClientOnly", policy => policy.RequireRole("Client", "Admin"));
            });






            builder.Services.AddScoped<ITokenService, TokenService>();







            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
