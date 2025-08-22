using MareSynchronosShared.Metrics;
using MareSynchronosShared.Services;
using MareSynchronosStaticFilesServer.Utils;
using System.Collections.Concurrent;
using System.Net.Http.Headers;
using MareSynchronosShared.Utils;
using MareSynchronos.API.Routes;
using MareSynchronosShared.Utils.Configuration;

namespace MareSynchronosStaticFilesServer.Services;

public sealed class CachedFileProvider : IDisposable
{
    private readonly IConfigurationService<StaticFilesServerConfiguration> _configuration;
    private readonly ILogger<CachedFileProvider> _logger;
    private readonly FileStatisticsService _fileStatisticsService;
    private readonly MareMetrics _metrics;
    private readonly ServerTokenGenerator _generator;
    private readonly ITouchHashService _touchService;
    private readonly Uri _remoteCacheSourceUri;
    private readonly bool _useColdStorage;
    private readonly string _hotStoragePath;
    private readonly string _coldStoragePath;
    private readonly ConcurrentDictionary<string, Task> _currentTransfers = new(StringComparer.Ordinal);
    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _downloadSemaphore = new(1, 1);
    private bool _disposed;

    private bool IsMainServer => _remoteCacheSourceUri == null && _isDistributionServer;
    private bool _isDistributionServer;

    public CachedFileProvider(IConfigurationService<StaticFilesServerConfiguration> configuration, ILogger<CachedFileProvider> logger,
        FileStatisticsService fileStatisticsService, MareMetrics metrics, ServerTokenGenerator generator, ITouchHashService touchService)
    {
        AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);
        _configuration = configuration;
        _logger = logger;
        _fileStatisticsService = fileStatisticsService;
        _metrics = metrics;
        _generator = generator;
        _touchService = touchService;
        _remoteCacheSourceUri = configuration.GetValueOrDefault<Uri>(nameof(StaticFilesServerConfiguration.DistributionFileServerAddress), null);
        _isDistributionServer = configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.IsDistributionNode), false);
        _useColdStorage = configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.UseColdStorage), false);
        _hotStoragePath = configuration.GetValue<string>(nameof(StaticFilesServerConfiguration.CacheDirectory));
        _coldStoragePath = configuration.GetValue<string>(nameof(StaticFilesServerConfiguration.ColdStorageDirectory));
        _httpClient = new();
        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("MareSynchronosServer", "1.0.0.0"));
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _httpClient?.Dispose();
    }

    private async Task DownloadTask(string hash)
    {
        var destinationFilePath = FilePathUtil.GetFilePath(_useColdStorage ? _coldStoragePath : _hotStoragePath, hash);

        // if cold storage is not configured or file not found or error is present try to download file from remote
        var downloadUrl = MareFiles.DistributionGetFullPath(_remoteCacheSourceUri, hash);
        _logger.LogInformation("Did not find {hash}, downloading from {server}", hash, downloadUrl);

        using var requestMessage = new HttpRequestMessage(HttpMethod.Get, downloadUrl);
        requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _generator.Token);
        if (_configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.DistributionFileServerForceHTTP2), false))
        {
            requestMessage.Version = new Version(2, 0);
            requestMessage.VersionPolicy = HttpVersionPolicy.RequestVersionExact;
        }
        HttpResponseMessage? response = null;

        try
        {
            response = await _httpClient.SendAsync(requestMessage).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to download {url}", downloadUrl);
            response?.Dispose();
            return;
        }

        var tempFileName = destinationFilePath + ".dl";
        var fileStream = new FileStream(tempFileName, FileMode.Create, FileAccess.ReadWrite);
        var bufferSize = 4096;
        var buffer = new byte[bufferSize];

        var bytesRead = 0;
        using var content = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        while ((bytesRead = await content.ReadAsync(buffer).ConfigureAwait(false)) > 0)
        {
            await fileStream.WriteAsync(buffer.AsMemory(0, bytesRead)).ConfigureAwait(false);
        }
        await fileStream.FlushAsync().ConfigureAwait(false);
        await fileStream.DisposeAsync().ConfigureAwait(false);
        File.Move(tempFileName, destinationFilePath, true);

        _metrics.IncGauge(_useColdStorage ? MetricsAPI.GaugeFilesTotalColdStorage : MetricsAPI.GaugeFilesTotal);
        _metrics.IncGauge(_useColdStorage ? MetricsAPI.GaugeFilesTotalSizeColdStorage : MetricsAPI.GaugeFilesTotalSize, new FileInfo(destinationFilePath).Length);
        response.Dispose();
    }

    private bool TryCopyFromColdStorage(string hash, string destinationFilePath)
    {
        if (!_useColdStorage) return false;

        if (string.IsNullOrEmpty(_coldStoragePath)) return false;

        var coldStorageFilePath = FilePathUtil.GetFilePath(_coldStoragePath, hash);
        if (!File.Exists(coldStorageFilePath)) return false;

        try
        {
            _logger.LogDebug("Copying {hash} from cold storage: {path}", hash, coldStorageFilePath);
            var tempFileName = destinationFilePath + ".dl";
            File.Copy(coldStorageFilePath, tempFileName, true);
            File.Move(tempFileName, destinationFilePath, true);
            var destinationFile = new FileInfo(destinationFilePath);
            _metrics.IncGauge(MetricsAPI.GaugeFilesTotal);
            _metrics.IncGauge(MetricsAPI.GaugeFilesTotalSize, new FileInfo(destinationFilePath).Length);
            return true;
        }
        catch (Exception ex)
        {
            // Recover from a fairly common race condition -- max wait time is 75ms
            // Having TryCopyFromColdStorage protected by the downloadtask mutex doesn't work for some reason?
            for (int retry = 0; retry < 5; ++retry)
            {
                Thread.Sleep(5 + retry * 5);
                if (File.Exists(destinationFilePath))
                    return true;
            }
            _logger.LogWarning(ex, "Could not copy {coldStoragePath} from cold storage", coldStorageFilePath);
        }

        return false;
    }

    // Returns FileInfo ONLY if the hot file was immediately available without downloading
    // Since the intended use is for pre-fetching files from hot storage, this is exactly what we need anyway
    public async Task<FileInfo?> DownloadFileWhenRequired(string hash)
    {
        var fi = FilePathUtil.GetFileInfoForHash(_hotStoragePath, hash);

        if (fi != null && fi.Length != 0)
            return fi;

        // first check cold storage
        if (TryCopyFromColdStorage(hash, FilePathUtil.GetFilePath(_hotStoragePath, hash)))
            return null;

        // no distribution server configured to download from
        if (_remoteCacheSourceUri == null)
            return null;

        await _downloadSemaphore.WaitAsync().ConfigureAwait(false);
        if (!_currentTransfers.TryGetValue(hash, out var downloadTask) || (downloadTask?.IsCompleted ?? true))
        {
            _currentTransfers[hash] = Task.Run(async () =>
            {
                try
                {
                    _metrics.IncGauge(MetricsAPI.GaugeFilesDownloadingFromCache);
                    await DownloadTask(hash).ConfigureAwait(false);
                    TryCopyFromColdStorage(hash, FilePathUtil.GetFilePath(_hotStoragePath, hash));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error during Download Task for {hash}", hash);
                }
                finally
                {
                    _metrics.DecGauge(MetricsAPI.GaugeFilesDownloadingFromCache);
                    _currentTransfers.Remove(hash, out _);
                }
            });
        }
        _downloadSemaphore.Release();

        return null;
    }

    public async Task<FileInfo?> GetAndDownloadFile(string hash)
    {
        var fi = await DownloadFileWhenRequired(hash).ConfigureAwait(false);

        if (fi == null && _currentTransfers.TryGetValue(hash, out var downloadTask))
        {
            try
            {
                using CancellationTokenSource cts = new();
                cts.CancelAfter(TimeSpan.FromSeconds(120));
                _metrics.IncGauge(MetricsAPI.GaugeFilesTasksWaitingForDownloadFromCache);
                await downloadTask.WaitAsync(cts.Token).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                _logger.LogWarning(e, "Failed while waiting for download task for {hash}", hash);
                return null;
            }
            finally
            {
                _metrics.DecGauge(MetricsAPI.GaugeFilesTasksWaitingForDownloadFromCache);
            }
        }

        fi ??= FilePathUtil.GetFileInfoForHash(_hotStoragePath, hash);

        if (fi == null)
            return null;

        fi.LastAccessTimeUtc = DateTime.UtcNow;
        _touchService.TouchColdHash(hash);

        _fileStatisticsService.LogFile(hash, fi.Length);

        return fi;
    }

    public async Task<FileStream?> GetAndDownloadFileStream(string hash)
    {
        var fi = await GetAndDownloadFile(hash).ConfigureAwait(false);
        return new FileStream(fi.FullName, FileMode.Open, FileAccess.Read, FileShare.Inheritable | FileShare.Read);
    }

    public void TouchColdHash(string hash)
    {
        _touchService.TouchColdHash(hash);
    }

    public bool AnyFilesDownloading(List<string> hashes)
    {
        return hashes.Exists(_currentTransfers.Keys.Contains);
    }
}