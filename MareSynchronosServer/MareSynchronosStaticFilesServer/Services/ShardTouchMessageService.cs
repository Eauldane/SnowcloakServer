using MareSynchronos.API.Routes;
using MareSynchronosShared.Services;
using MareSynchronosShared.Utils;
using MareSynchronosShared.Utils.Configuration;
using System.Net.Http.Headers;

namespace MareSynchronosStaticFilesServer.Services;

// Notify distribution server of file hashes downloaded via shards, so they are not prematurely purged from its cold cache
public class ShardTouchMessageService : ITouchHashService
{
    private readonly ILogger<ShardTouchMessageService> _logger;
    private readonly ServerTokenGenerator _tokenGenerator;
    private readonly IConfigurationService<StaticFilesServerConfiguration> _configuration;
    private readonly HttpClient _httpClient;
    private readonly Uri _remoteCacheSourceUri;
    private readonly HashSet<string> _touchHashSet = new();
    private readonly ColdTouchHashService _nestedService = null;

    private CancellationTokenSource _touchmsgCts;

    public ShardTouchMessageService(ILogger<ShardTouchMessageService> logger, ILogger<ColdTouchHashService> nestedLogger,
        ServerTokenGenerator tokenGenerator, IConfigurationService<StaticFilesServerConfiguration> configuration)
    {
        _logger = logger;
        _tokenGenerator = tokenGenerator;
        _configuration = configuration;
        _remoteCacheSourceUri = _configuration.GetValueOrDefault<Uri>(nameof(StaticFilesServerConfiguration.DistributionFileServerAddress), null);
        _httpClient = new();
        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("MareSynchronosServer", "1.0.0.0"));

        if (configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.UseColdStorage), false))
        {
            _nestedService = new ColdTouchHashService(nestedLogger, configuration);
        }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_remoteCacheSourceUri == null)
            return Task.CompletedTask;

        _logger.LogInformation("Touch Message Service started");

        _touchmsgCts = new();

        _ = TouchMessageTask(_touchmsgCts.Token);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        if (_remoteCacheSourceUri == null)
            return Task.CompletedTask;

        _touchmsgCts.Cancel();

        return Task.CompletedTask;
    }

    private async Task SendTouches(IEnumerable<string> hashes)
    {
        var mainUrl = _remoteCacheSourceUri;
        var path = new Uri(mainUrl, MareFiles.Distribution + "/touch");
        using HttpRequestMessage msg = new()
        {
            RequestUri = path
        };
        msg.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _tokenGenerator.Token);
        msg.Method = HttpMethod.Post;
        msg.Content = JsonContent.Create(hashes);
        if (_configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.DistributionFileServerForceHTTP2), false))
        {
            msg.Version = new Version(2, 0);
            msg.VersionPolicy = HttpVersionPolicy.RequestVersionExact;
        }

        _logger.LogDebug("Sending remote touch to {path}", path);
        try
        {
            using var result = await _httpClient.SendAsync(msg).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failure to send touches for {hashChunk}", hashes);
        }
    }

    private async Task TouchMessageTask(CancellationToken ct)
    {
        List<string> hashes;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                lock (_touchHashSet)
                {
                    hashes = _touchHashSet.ToList();
                    _touchHashSet.Clear();
                }
                if (hashes.Count > 0)
                    await SendTouches(hashes).ConfigureAwait(false);
                await Task.Delay(TimeSpan.FromSeconds(60), ct).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error during touch message task");
            }
        }

        lock (_touchHashSet)
        {
            hashes = _touchHashSet.ToList();
            _touchHashSet.Clear();
        }
        if (hashes.Count > 0)
            await SendTouches(hashes).ConfigureAwait(false);
    }

    public void TouchColdHash(string hash)
    {
        if (_nestedService != null)
            _nestedService.TouchColdHash(hash);

        lock (_touchHashSet)
        {
            _touchHashSet.Add(hash);
        }
    }
}
