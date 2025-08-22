using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Threading.Channels;

namespace MareSynchronosStaticFilesServer.Services;

// Pre-fetch files from cache storage in to memory
public class FilePreFetchService : IHostedService
{
    private struct PreFetchRequest
    {
        public FileInfo FileInfo;
        public DateTime ExpiryUtc;
    }

    private readonly ILogger<FilePreFetchService> _logger;

    private CancellationTokenSource _prefetchCts;
    private readonly Channel<PreFetchRequest> _prefetchChannel;

    private const int _readAheadBytes = 8 * 1024 * 1024; // Maximum number of of bytes to prefetch per file (8MB)
    private const int _preFetchTasks = 4; // Maximum number of tasks to process prefetches concurrently

    // Use readahead() on linux if its available
    [DllImport("libc", EntryPoint = "readahead")]
    static extern int LinuxReadAheadExternal(SafeFileHandle fd, Int64 offset, int count);

    private bool _hasLinuxReadAhead = true;

    public FilePreFetchService(ILogger<FilePreFetchService> logger)
    {
        _logger = logger;
        _prefetchChannel = Channel.CreateUnbounded<PreFetchRequest>();
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("File PreFetch Service started");
        _prefetchCts = new();
        for (int i = 0; i < _preFetchTasks; ++i)
            _ = PrefetchTask(_prefetchCts.Token);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _prefetchCts.Cancel();
        return Task.CompletedTask;
    }

    // Queue a list of hashes to be prefetched in a background task
    public void PrefetchFiles(ICollection<FileInfo> fileList)
    {
        if (!_hasLinuxReadAhead)
        {
            if (!_prefetchCts.IsCancellationRequested)
            {
                _logger.LogError("readahead() is not available - aborting File PreFetch Service");
                _prefetchCts.Cancel();
            }
            return;
        }

        var nowUtc = DateTime.UtcNow;

        // Expire prefetch requests that aren't picked up within 500ms
        // By this point the request is probably already being served, or things are moving too slow to matter anyway
        var expiry = nowUtc + TimeSpan.FromMilliseconds(500);

        foreach (var fileInfo in fileList)
        {
            _ = _prefetchChannel.Writer.TryWrite(new PreFetchRequest(){
                FileInfo = fileInfo,
                ExpiryUtc = expiry,
            });
        }
    }

    private async Task PrefetchTask(CancellationToken ct)
    {
        var reader = _prefetchChannel.Reader;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var req = await reader.ReadAsync(ct).ConfigureAwait(false);
                var nowUtc = DateTime.UtcNow;

                if (nowUtc >= req.ExpiryUtc)
                {
                    _logger.LogDebug("Skipped expired prefetch for {hash}", req.FileInfo.Name);
                    continue;
                }

                try
                {
                    var fs = new FileStream(req.FileInfo.FullName, FileMode.Open, FileAccess.Read, FileShare.Inheritable | FileShare.Read);

                    await using (fs.ConfigureAwait(false))
                    {
                        try
                        {
                            _ = LinuxReadAheadExternal(fs.SafeFileHandle, 0, _readAheadBytes);
                            _logger.LogTrace("Prefetched {hash}", req.FileInfo.Name);
                        }
                        catch (EntryPointNotFoundException)
                        {
                            _hasLinuxReadAhead = false;
                        }
                    }
                }
                catch (IOException) { }
            }
            catch (OperationCanceledException)
            {
                continue;
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error during prefetch task");
            }
        }
    }
}
