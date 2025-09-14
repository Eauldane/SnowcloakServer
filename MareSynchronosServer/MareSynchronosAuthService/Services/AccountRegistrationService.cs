using System.Collections.Concurrent;
using MareSynchronos.API.Dto.Account;
using MareSynchronosShared.Data;
using MareSynchronosShared.Metrics;
using MareSynchronosShared.Services;
using MareSynchronosShared.Utils;
using MareSynchronosShared.Utils.Configuration;
using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;
using MareSynchronosShared.Models;
using StackExchange.Redis;
using StackExchange.Redis.Extensions.Core.Abstractions;

namespace MareSynchronosAuthService.Services;

public class AccountRegistrationService
{
    private readonly MareMetrics _metrics;
    private readonly MareDbContext _mareDbContext;
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly IConfigurationService<AuthServiceConfiguration> _configurationService;
    private readonly ILogger<AccountRegistrationService> _logger;
    private readonly IRedisDatabase _redis;

    

    public AccountRegistrationService(MareMetrics metrics, MareDbContext mareDbContext,
		IServiceScopeFactory serviceScopeFactory, IConfigurationService<AuthServiceConfiguration> configuration,
		ILogger<AccountRegistrationService> logger, IRedisDatabase redisDb)
    {
        _mareDbContext = mareDbContext;
        _logger = logger;
        _configurationService = configuration;
        _metrics = metrics;
        _serviceScopeFactory = serviceScopeFactory;
        _redis = redisDb;
    }

    public async Task<RegisterReplyV2Dto> RegisterAccountAsync(string ua, string ip, string hashedSecretKey)
    {
		var reply = new RegisterReplyV2Dto();

		if (string.IsNullOrEmpty(ua) || !ua.StartsWith("MareSynchronos/", StringComparison.Ordinal))
        {
            reply.ErrorMessage = "User-Agent not allowed";
            return reply;
        }

        var registrationsByIp = await _redis.GetAsync<int>("IPREG:" + ip).ConfigureAwait(false);
        if (registrationsByIp >= _configurationService.GetValueOrDefault(nameof(AuthServiceConfiguration.RegisterIpLimit), 3))
        {
            reply.ErrorMessage = "Too many registrations from this IP. Please try again later.";
            return reply;
        }

        var user = new User();

        var hasValidUid = false;
        while (!hasValidUid)
        {
            var uid = StringUtils.GenerateRandomString(8);
            if (_mareDbContext.Users.Any(u => u.UID == uid || u.Alias == uid)) continue;
            user.UID = uid;
            hasValidUid = true;
        }

        user.LastLoggedIn = DateTime.UtcNow;

        var auth = new Auth()
        {
            HashedKey = hashedSecretKey,
            User = user,
        };

        await _mareDbContext.Users.AddAsync(user).ConfigureAwait(false);
        await _mareDbContext.Auth.AddAsync(auth).ConfigureAwait(false);
		await _mareDbContext.SaveChangesAsync().ConfigureAwait(false);

        _logger.LogInformation("User registered: {userUID} from IP {ip}", user.UID, ip);
        _metrics.IncCounter(MetricsAPI.CounterAccountsCreated);

        reply.Success = true;
        reply.UID = user.UID;

        
        await _redis.Database.StringIncrementAsync($"IPREG:{ip}").ConfigureAwait(false);
        // Naive implementation, but should be good enough. A true sliding window *probably* isn't necessary.
        await _redis.Database.KeyExpireAsync($"IPREG:{ip}", TimeSpan.
            FromMinutes(_configurationService.GetValueOrDefault(nameof(
                AuthServiceConfiguration.RegisterIpDurationInMinutes), 60))).
            ConfigureAwait(false); 

		return reply;
    }
}
