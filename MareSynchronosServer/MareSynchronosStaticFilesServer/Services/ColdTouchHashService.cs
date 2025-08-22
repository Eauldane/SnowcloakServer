using MareSynchronosShared.Services;
using MareSynchronosShared.Utils.Configuration;
using MareSynchronosStaticFilesServer.Utils;
using System.Collections.Concurrent;

namespace MareSynchronosStaticFilesServer.Services;

// Perform access time updates for cold cache files accessed via hot cache or shard servers
public class ColdTouchHashService : ITouchHashService
{
    private readonly ILogger<ColdTouchHashService> _logger;
    private readonly IConfigurationService<StaticFilesServerConfiguration> _configuration;

    private readonly bool _useColdStorage;
    private readonly string _coldStoragePath;

    // Debounce multiple updates towards the same file
    private readonly ConcurrentDictionary<string, DateTime> _lastUpdateTimesUtc = new(StringComparer.Ordinal);
    private int _cleanupCounter = 0;
    private object _cleanupLockObj = new();
    private const double _debounceTimeSecs = 900.0;

    public ColdTouchHashService(ILogger<ColdTouchHashService> logger, IConfigurationService<StaticFilesServerConfiguration> configuration)
    {
        _logger = logger;
        _configuration = configuration;
        _useColdStorage = configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.UseColdStorage), false);
        _coldStoragePath = configuration.GetValue<string>(nameof(StaticFilesServerConfiguration.ColdStorageDirectory));
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public void TouchColdHash(string hash)
    {
        if (!_useColdStorage)
            return;

        var nowUtc = DateTime.UtcNow;

        // Clean up debounce dictionary regularly
        if (_cleanupCounter++ >= 1000)
        {
            _cleanupCounter = 0;
            if (Monitor.TryEnter(_cleanupLockObj))
            {
                try
                {
                    foreach (var entry in _lastUpdateTimesUtc.Where(entry => (nowUtc - entry.Value).TotalSeconds >= _debounceTimeSecs).ToList())
                        _lastUpdateTimesUtc.TryRemove(entry.Key, out _);
                }
                finally
                {
                    Monitor.Exit(_cleanupLockObj);
                }
            }
        }

        // Ignore multiple updates within a time window of the first
        if (_lastUpdateTimesUtc.TryGetValue(hash, out var lastUpdateTimeUtc) && (nowUtc - lastUpdateTimeUtc).TotalSeconds < _debounceTimeSecs)
            return;

        var fileInfo = FilePathUtil.GetFileInfoForHash(_coldStoragePath, hash);
        if (fileInfo != null)
        {
            _logger.LogTrace("Touching {fileName}", fileInfo.Name);
            try
            {
                fileInfo.LastAccessTimeUtc = nowUtc;
            }
            catch (IOException) { return; }
            _lastUpdateTimesUtc.TryAdd(hash, nowUtc);
        }
    }
}
