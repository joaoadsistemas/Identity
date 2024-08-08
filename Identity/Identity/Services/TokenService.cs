

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Identity.Interfaces;

namespace Lawyer.Application.Services
{
    public class TokenService : ITokenService
    {

        public JwtSecurityToken GenerateAccessToken(IEnumerable<Claim> claims, IConfiguration _config)
        {
            // Recupera a chave secreta da configuração
            var key = _config["TokenSettings:SecretKey"] ??
                throw new InvalidOperationException("Chave Secreta Inválida");

            // Converte a chave em bytes
            var privateKey = Encoding.UTF8.GetBytes(key);

            // Configura as credenciais de assinatura usando HMAC SHA-256
            var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(privateKey), SecurityAlgorithms.HmacSha256Signature);

            // Configura os detalhes do token
            var tokenDescriptor = new SecurityTokenDescriptor
            {

                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(double.Parse(_config["TokenSettings:RefreshTokenValidityInMinutes"])),
                Audience = _config["TokenSettings:ValidAudience"],
                Issuer = _config["TokenSettings:ValidIssuer"],
                SigningCredentials = signingCredentials,
            };

            // Cria um token JWT usando o handler
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            return token;
        }

        public string GenerateRefreshToken()
        {
            // Gera bytes aleatórios seguros
            var secureRandomBytes = new byte[128];

            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(secureRandomBytes);

            // Converte os bytes em uma string Base64
            var refreshToken = Convert.ToBase64String(secureRandomBytes);
            return refreshToken;
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token, IConfiguration _config)
        {
            // Recupera a chave secreta da configuração
            var secretKey = _config["TokenSettings:SecretKey"] ?? throw new InvalidOperationException("Chave Inválida");

            // Configura os parâmetros de validação do token
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
                ValidateLifetime = false,
            };

            // Valida o token e obtém o principal
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            // Verifica se o token é do tipo JWT e usa o algoritmo HMAC SHA-256
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Token Inválido");
            }

            return principal;
        }
    }
    
}
