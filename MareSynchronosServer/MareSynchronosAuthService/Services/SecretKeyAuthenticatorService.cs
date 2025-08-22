using System.Collections.Concurrent;
using MareSynchronosAuthService.Authentication;
using MareSynchronosShared.Data;
using MareSynchronosShared.Metrics;
using MareSynchronosShared.Services;
using MareSynchronosShared.Utils.Configuration;
using Microsoft.EntityFrameworkCore;

namespace MareSynchronosAuthService.Services;

public class SecretKeyAuthenticatorService
{
    private readonly MareMetrics _metrics;
    private readonly MareDbContext _mareDbContext;
    private readonly IConfigurationService<AuthServiceConfiguration> _configurationService;
    private readonly ILogger<SecretKeyAuthenticatorService> _logger;
    private readonly ConcurrentDictionary<string, SecretKeyFailedAuthorization> _failedAuthorizations = new(StringComparer.Ordinal);

    public SecretKeyAuthenticatorService(MareMetrics metrics, MareDbContext mareDbContext,
        IConfigurationService<AuthServiceConfiguration> configuration, ILogger<SecretKeyAuthenticatorService> logger)
    {
        _logger = logger;
        _configurationService = configuration;
        _metrics = metrics;
        _mareDbContext = mareDbContext;
    }

    public async Task<SecretKeyAuthReply> AuthorizeAsync(string ip, string hashedSecretKey)
    {
        _metrics.IncCounter(MetricsAPI.CounterAuthenticationRequests);

        if (_failedAuthorizations.TryGetValue(ip, out var existingFailedAuthorization)
            && existingFailedAuthorization.FailedAttempts > _configurationService.GetValueOrDefault(nameof(AuthServiceConfiguration.FailedAuthForTempBan), 5))
        {
            if (existingFailedAuthorization.ResetTask == null)
            {
                _logger.LogWarning("TempBan {ip} for authorization spam", ip);

                existingFailedAuthorization.ResetTask = Task.Run(async () =>
                {
                    await Task.Delay(TimeSpan.FromMinutes(_configurationService.GetValueOrDefault(nameof(AuthServiceConfiguration.TempBanDurationInMinutes), 5))).ConfigureAwait(false);

                }).ContinueWith((t) =>
                {
                    _failedAuthorizations.Remove(ip, out _);
                });
            }
            return new(Success: false, Uid: null, TempBan: true, Alias: null, Permaban: false);
        }

        var authReply = await _mareDbContext.Auth.Include(a => a.User).AsNoTracking()
            .SingleOrDefaultAsync(u => u.HashedKey == hashedSecretKey).ConfigureAwait(false);

        SecretKeyAuthReply reply = new(authReply != null, authReply?.UserUID, authReply?.User?.Alias ?? string.Empty, TempBan: false, authReply?.IsBanned ?? false);

        if (reply.Success)
        {
            _metrics.IncCounter(MetricsAPI.CounterAuthenticationSuccesses);
        }
        else
        {
            return AuthenticationFailure(ip);
        }

        return reply;
    }

    private SecretKeyAuthReply AuthenticationFailure(string ip)
    {
        _metrics.IncCounter(MetricsAPI.CounterAuthenticationFailures);

        _logger.LogWarning("Failed authorization from {ip}", ip);
        var whitelisted = _configurationService.GetValueOrDefault(nameof(AuthServiceConfiguration.WhitelistedIps), new List<string>());
        if (!whitelisted.Any(w => ip.Contains(w, StringComparison.OrdinalIgnoreCase)))
        {
            if (_failedAuthorizations.TryGetValue(ip, out var auth))
            {
                auth.IncreaseFailedAttempts();
            }
            else
            {
                _failedAuthorizations[ip] = new SecretKeyFailedAuthorization();
            }
        }

        return new(Success: false, Uid: null, Alias: null, TempBan: false, Permaban: false);
    }
}
