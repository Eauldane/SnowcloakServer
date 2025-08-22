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

namespace MareSynchronosAuthService.Services;

internal record IpRegistrationCount
{
    private int count = 1;
    public int Count => count;
    public Task ResetTask { get; set; }
	public CancellationTokenSource ResetTaskCts { get; set; }
    public void IncreaseCount()
    {
        Interlocked.Increment(ref count);
    }
}

public class AccountRegistrationService
{
    private readonly MareMetrics _metrics;
    private readonly MareDbContext _mareDbContext;
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly IConfigurationService<AuthServiceConfiguration> _configurationService;
    private readonly ILogger<AccountRegistrationService> _logger;
    private readonly ConcurrentDictionary<string, IpRegistrationCount> _registrationsPerIp = new(StringComparer.Ordinal);

    private Regex _registrationUserAgentRegex = new Regex(@"^MareSynchronos/", RegexOptions.Compiled);

    public AccountRegistrationService(MareMetrics metrics, MareDbContext mareDbContext,
		IServiceScopeFactory serviceScopeFactory, IConfigurationService<AuthServiceConfiguration> configuration,
		ILogger<AccountRegistrationService> logger)
    {
        _mareDbContext = mareDbContext;
        _logger = logger;
        _configurationService = configuration;
        _metrics = metrics;
        _serviceScopeFactory = serviceScopeFactory;
    }

    public async Task<RegisterReplyV2Dto> RegisterAccountAsync(string ua, string ip, string hashedSecretKey)
    {
		var reply = new RegisterReplyV2Dto();

		if (!_registrationUserAgentRegex.Match(ua).Success)
        {
            reply.ErrorMessage = "User-Agent not allowed";
            return reply;
        }

        if (_registrationsPerIp.TryGetValue(ip, out var registrationCount)
            && registrationCount.Count >= _configurationService.GetValueOrDefault(nameof(AuthServiceConfiguration.RegisterIpLimit), 3))
        {
            _logger.LogWarning("Rejecting {ip} for registration spam", ip);

            if (registrationCount.ResetTask == null)
            {
				registrationCount.ResetTaskCts = new CancellationTokenSource();

				if (registrationCount.ResetTaskCts != null)
					registrationCount.ResetTaskCts.Cancel();

                registrationCount.ResetTask = Task.Run(async () =>
                {
                    await Task.Delay(TimeSpan.FromMinutes(_configurationService.GetValueOrDefault(nameof(AuthServiceConfiguration.RegisterIpDurationInMinutes), 10))).ConfigureAwait(false);

                }).ContinueWith((t) =>
                {
                    _registrationsPerIp.Remove(ip, out _);
                }, registrationCount.ResetTaskCts.Token);
            }
            reply.ErrorMessage = "Too many registrations from this IP. Please try again later.";
            return reply;
        }

        var user = new User();

        var hasValidUid = false;
        while (!hasValidUid)
        {
            var uid = StringUtils.GenerateRandomString(7);
            if (_mareDbContext.Users.Any(u => u.UID == uid || u.Alias == uid)) continue;
            user.UID = uid;
            hasValidUid = true;
        }

        // make the first registered user on the service to admin
        if (!await _mareDbContext.Users.AnyAsync().ConfigureAwait(false))
        {
            user.IsAdmin = true;
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

        RecordIpRegistration(ip);

		return reply;
    }

    private void RecordIpRegistration(string ip)
    {
        var whitelisted = _configurationService.GetValueOrDefault(nameof(AuthServiceConfiguration.WhitelistedIps), new List<string>());
        if (!whitelisted.Any(w => ip.Contains(w, StringComparison.OrdinalIgnoreCase)))
        {
            if (_registrationsPerIp.TryGetValue(ip, out var count))
            {
                count.IncreaseCount();
            }
            else
            {
                count = _registrationsPerIp[ip] = new IpRegistrationCount();

				if (count.ResetTaskCts != null)
					count.ResetTaskCts.Cancel();

				count.ResetTaskCts = new CancellationTokenSource();

                count.ResetTask = Task.Run(async () =>
                {
                    await Task.Delay(TimeSpan.FromMinutes(_configurationService.GetValueOrDefault(nameof(AuthServiceConfiguration.RegisterIpDurationInMinutes), 10))).ConfigureAwait(false);

                }).ContinueWith((t) =>
                {
                    _registrationsPerIp.Remove(ip, out _);
                }, count.ResetTaskCts.Token);
            }
        }
    }
}
