using MareSynchronos.API.Dto;
using MareSynchronos.API.Dto.Account;
using MareSynchronos.API.Routes;
using MareSynchronosAuthService.Services;
using MareSynchronosShared;
using MareSynchronosShared.Data;
using MareSynchronosShared.Models;
using MareSynchronosShared.Services;
using MareSynchronosShared.Utils;
using MareSynchronosShared.Utils.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis.Extensions.Core.Abstractions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MareSynchronosAuthService.Controllers;

[AllowAnonymous]
[Route(MareAuth.Auth)]
public class JwtController : Controller
{
    private readonly IHttpContextAccessor _accessor;
    private readonly IRedisDatabase _redis;
    private readonly IDbContextFactory<MareDbContext> _mareDbContextFactory;
    private readonly GeoIPService _geoIPProvider;
    private readonly SecretKeyAuthenticatorService _secretKeyAuthenticatorService;
    private readonly AccountRegistrationService _accountRegistrationService;
    private readonly IConfigurationService<AuthServiceConfiguration> _configuration;

    public JwtController(ILogger<JwtController> logger,
        IHttpContextAccessor accessor, IDbContextFactory<MareDbContext> mareDbContextFactory,
        SecretKeyAuthenticatorService secretKeyAuthenticatorService,
        AccountRegistrationService accountRegistrationService,
        IConfigurationService<AuthServiceConfiguration> configuration,
        IRedisDatabase redisDb, GeoIPService geoIPProvider)
    {
        _accessor = accessor;
        _redis = redisDb;
        _geoIPProvider = geoIPProvider;
        _mareDbContextFactory = mareDbContextFactory;
        _secretKeyAuthenticatorService = secretKeyAuthenticatorService;
        _accountRegistrationService = accountRegistrationService;
        _configuration = configuration;
    }

    [AllowAnonymous]
    [HttpPost(MareAuth.Auth_CreateIdent)]
    public async Task<IActionResult> CreateToken(string auth, string charaIdent)
    {
        if (string.IsNullOrEmpty(auth)) return BadRequest("No Authkey");
        if (string.IsNullOrEmpty(charaIdent)) return BadRequest("No CharaIdent");

        using var dbContext = await _mareDbContextFactory.CreateDbContextAsync();
        var ip = _accessor.GetIpAddress();

        var authResult = await _secretKeyAuthenticatorService.AuthorizeAsync(ip, auth);

        var isBanned = await dbContext.BannedUsers.AsNoTracking().AnyAsync(u => u.CharacterIdentification == charaIdent).ConfigureAwait(false);
        if (isBanned)
        {
            var authToBan = dbContext.Auth.SingleOrDefault(a => a.UserUID == authResult.Uid);
            if (authToBan != null)
            {
                authToBan.IsBanned = true;
                await dbContext.SaveChangesAsync().ConfigureAwait(false);
            }

            return Unauthorized("Your character is banned from using the service.");
        }

        if (!authResult.Success && !authResult.TempBan) return Unauthorized("The provided secret key is invalid. Verify your accounts existence and/or recover the secret key.");
        if (!authResult.Success && authResult.TempBan) return Unauthorized("Due to an excessive amount of failed authentication attempts you are temporarily banned. Check your Secret Key configuration and try connecting again in 5 minutes.");
        if (authResult.Permaban)
        {
            if (!dbContext.BannedUsers.Any(c => c.CharacterIdentification == charaIdent))
            {
                dbContext.BannedUsers.Add(new Banned()
                {
                    CharacterIdentification = charaIdent,
                    Reason = "Autobanned CharacterIdent (" + authResult.Uid + ")",
                });

                await dbContext.SaveChangesAsync();
            }

            var lodestone = await dbContext.LodeStoneAuth.Include(a => a.User).FirstOrDefaultAsync(c => c.User.UID == authResult.Uid);

            if (lodestone != null)
            {
                if (!dbContext.BannedRegistrations.Any(c => c.DiscordIdOrLodestoneAuth == lodestone.HashedLodestoneId))
                {
                    dbContext.BannedRegistrations.Add(new BannedRegistrations()
                    {
                        DiscordIdOrLodestoneAuth = lodestone.HashedLodestoneId,
                    });
                }
                if (!dbContext.BannedRegistrations.Any(c => c.DiscordIdOrLodestoneAuth == lodestone.DiscordId.ToString()))
                {
                    dbContext.BannedRegistrations.Add(new BannedRegistrations()
                    {
                        DiscordIdOrLodestoneAuth = lodestone.DiscordId.ToString(),
                    });
                }

                await dbContext.SaveChangesAsync();
            }

            return Unauthorized("You are permanently banned.");
        }

        var existingIdent = await _redis.GetAsync<string>("UID:" + authResult.Uid);
        if (!string.IsNullOrEmpty(existingIdent)) return Unauthorized("Already logged in to this account. Reconnect in 60 seconds. If you keep seeing this issue, restart your game.");

        var token = CreateToken(new List<Claim>()
        {
            new Claim(MareClaimTypes.Uid, authResult.Uid),
            new Claim(MareClaimTypes.CharaIdent, charaIdent),
            new Claim(MareClaimTypes.Alias, authResult.Alias),
            new Claim(MareClaimTypes.Continent, await _geoIPProvider.GetCountryFromIP(_accessor)),
        });

        return Content(token.RawData);
    }

    [AllowAnonymous]
    [HttpPost(MareAuth.Auth_CreateIdentV2)]
    public async Task<IActionResult> CreateTokenV2(string auth, string charaIdent)
    {
        var tokenResponse = await CreateToken(auth, charaIdent);
        var tokenContent = tokenResponse as ContentResult;
        if (tokenContent == null)
            return tokenResponse;
        return Json(new AuthReplyDto
        {
            Token = tokenContent.Content,
            WellKnown = _configuration.GetValueOrDefault(nameof(AuthServiceConfiguration.WellKnown), string.Empty),
        });
    }

    [AllowAnonymous]
    [HttpPost(MareAuth.Auth_Register)]
    public async Task<IActionResult> Register()
    {
        var ua = HttpContext.Request.Headers["User-Agent"][0] ?? "-";
        var ip = _accessor.GetIpAddress();

        // Legacy endpoint: generate a secret key for the user
        var computedHash = StringUtils.Sha256String(StringUtils.GenerateRandomString(64) + DateTime.UtcNow.ToString());
        var hashedKey = StringUtils.Sha256String(computedHash);

        var dto = await _accountRegistrationService.RegisterAccountAsync(ua, ip, hashedKey);

        return Json(new RegisterReplyDto()
        {
            Success = dto.Success,
            ErrorMessage = dto.ErrorMessage,
            UID = dto.UID,
            SecretKey = computedHash
        });
    }

    [AllowAnonymous]
    [HttpPost(MareAuth.Auth_RegisterV2)]
    public async Task<IActionResult> RegisterV2(string hashedSecretKey)
    {
        if (string.IsNullOrEmpty(hashedSecretKey)) return BadRequest("No HashedSecretKey");
        if (hashedSecretKey.Length != 64) return BadRequest("Bad HashedSecretKey");
        if (!hashedSecretKey.All(char.IsAsciiHexDigitUpper)) return BadRequest("Bad HashedSecretKey");

        var ua = HttpContext.Request.Headers["User-Agent"][0] ?? "-";
        var ip = _accessor.GetIpAddress();
        return Json(await _accountRegistrationService.RegisterAccountAsync(ua, ip, hashedSecretKey));
    }

    private JwtSecurityToken CreateToken(IEnumerable<Claim> authClaims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration.GetValue<string>(nameof(MareConfigurationBase.Jwt))));

        var token = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(authClaims),
            SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256Signature),
        };

        var handler = new JwtSecurityTokenHandler();
        return handler.CreateJwtSecurityToken(token);
    }
}

