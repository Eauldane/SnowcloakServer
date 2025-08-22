using ByteSizeLib;
using MareSynchronos.API.Dto.Files;
using MareSynchronosShared.Data;
using MareSynchronosShared.Metrics;
using MareSynchronosShared.Models;
using MareSynchronosShared.Services;
using MareSynchronosShared.Utils.Configuration;
using MareSynchronosStaticFilesServer.Utils;
using MessagePack.Formatters;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting.Systemd;

namespace MareSynchronosStaticFilesServer.Services;

public class FileCleanupService : IHostedService
{
    private readonly IConfigurationService<StaticFilesServerConfiguration> _configuration;
    private readonly ILogger<FileCleanupService> _logger;
    private readonly MareMetrics _metrics;
    private readonly IServiceProvider _services;

    private readonly string _hotStoragePath;
    private readonly string _coldStoragePath;
    private readonly bool _isMain = false;
    private readonly bool _isDistributionNode = false;
    private readonly bool _useColdStorage = false;
    private HashSet<string> _orphanedFiles = new(StringComparer.Ordinal);

    private CancellationTokenSource _cleanupCts;

    private int HotStorageMinimumRetention => _configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.MinimumFileRetentionPeriodInDays), 7);
    private int HotStorageRetention => _configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.UnusedFileRetentionPeriodInDays), 14);
    private double HotStorageSize => _configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.CacheSizeHardLimitInGiB), -1.0);

    private int ColdStorageMinimumRetention => _configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.ColdStorageMinimumFileRetentionPeriodInDays), 60);
    private int ColdStorageRetention => _configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.ColdStorageUnusedFileRetentionPeriodInDays), 60);
    private double ColdStorageSize => _configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.ColdStorageSizeHardLimitInGiB), -1.0);

    private double SmallSizeKiB => _configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.CacheSmallSizeThresholdKiB), 64.0);
    private double LargeSizeKiB => _configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.CacheLargeSizeThresholdKiB), 1024.0);

    private int ForcedDeletionAfterHours => _configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.ForcedDeletionOfFilesAfterHours), -1);
    private int CleanupCheckMinutes => _configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.CleanupCheckInMinutes), 15);

    private List<FileInfo> GetAllHotFiles() => new DirectoryInfo(_hotStoragePath).GetFiles("*", SearchOption.AllDirectories)
                .Where(f => f != null && f.Name.Length == 40)
                .OrderBy(f => f.LastAccessTimeUtc).ToList();

    private List<FileInfo> GetAllColdFiles() => new DirectoryInfo(_coldStoragePath).GetFiles("*", SearchOption.AllDirectories)
                .Where(f => f != null && f.Name.Length == 40)
                .OrderBy(f => f.LastAccessTimeUtc).ToList();

    private List<FileInfo> GetTempFiles() => new DirectoryInfo(_useColdStorage ? _coldStoragePath : _hotStoragePath).GetFiles("*", SearchOption.AllDirectories)
                .Where(f => f != null && (f.Name.EndsWith(".dl", StringComparison.InvariantCultureIgnoreCase) || f.Name.EndsWith(".tmp", StringComparison.InvariantCultureIgnoreCase))).ToList();

    public FileCleanupService(MareMetrics metrics, ILogger<FileCleanupService> logger,
        IServiceProvider services, IConfigurationService<StaticFilesServerConfiguration> configuration)
    {
        _metrics = metrics;
        _logger = logger;
        _services = services;
        _configuration = configuration;
        _useColdStorage = _configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.UseColdStorage), false);
        _hotStoragePath = configuration.GetValue<string>(nameof(StaticFilesServerConfiguration.CacheDirectory));
        _coldStoragePath = configuration.GetValue<string>(nameof(StaticFilesServerConfiguration.ColdStorageDirectory));
        _isDistributionNode = configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.IsDistributionNode), false);
        _isMain = configuration.GetValue<Uri>(nameof(StaticFilesServerConfiguration.MainFileServerAddress)) == null && _isDistributionNode;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Cleanup Service started");

        InitializeGauges();

        _cleanupCts = new();

        _ = CleanUpTask(_cleanupCts.Token);

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _cleanupCts.Cancel();

        return Task.CompletedTask;
    }

    private List<string> CleanUpFilesBeyondSizeLimit(List<FileInfo> files, double sizeLimit, double minTTL, double maxTTL, CancellationToken ct)
    {
        var removedFiles = new List<string>();
        if (sizeLimit <= 0)
        {
            return removedFiles;
        }

        var smallSize = SmallSizeKiB * 1024.0;
        var largeSize = LargeSizeKiB * 1024.0;
        var now = DateTime.Now;

        // Avoid nonsense in future calculations
        if (smallSize < 0.0)
            smallSize = 0.0;

        if (largeSize < smallSize)
            largeSize = smallSize;

        if (minTTL < 0.0)
            minTTL = 0.0;

        if (maxTTL < minTTL)
            maxTTL = minTTL;

        // Calculates a deletion priority to prioritize deletion of larger files over a configured TTL range based on a file's size.
        // This is intended to be applied to the hot cache, as the cost of recovering many small files is greater than a single large file.
        // Example (minTTL=7, maxTTL=30):
        //  - A 10MB file was last accessed 5 days ago. Its calculated optimum TTL is 7 days. result = 0.7143
        //  - A 50kB file was last accessed 10 days ago. Its calculated optimum TTL is 30 days. result = 0.3333
        //  The larger file will be deleted with a higher priority than the smaller file.
        double CalculateTTLProgression(FileInfo file)
        {
            var fileLength = (double)file.Length;
            var fileAgeDays = (now - file.LastAccessTime).TotalDays;
            var sizeNorm = Math.Clamp((fileLength - smallSize) / (largeSize - smallSize), 0.0, 1.0);
            // Using Math.Sqrt(sizeNorm) would create a more logical scaling curve, but it barely matters
            var ttlDayRange = (maxTTL - minTTL) * (1.0 - sizeNorm);
            var daysPastMinTTL = Math.Max(fileAgeDays - minTTL, 0.0);
            // There is some creativity in choosing an upper bound here:
            //  - With no upper bound, any file larger than `largeSize` is always the highest priority for deletion once it passes its calculated TTL
            //  - With 1.0 as an upper bound, all files older than `maxTTL` will have the same priority regardless of size
            //  - Using maxTTL/minTTL chooses a logical cut-off point where any files old enough to be affected would have been cleaned up already
            var ttlProg = Math.Clamp(daysPastMinTTL / ttlDayRange, 0.0, maxTTL / minTTL);
            return ttlProg;
        }

        try
        {
            // Since we already have the file list sorted by access time, the list index is incorporated in to
            // the dictionary key to preserve it as a secondary ordering
            var sortedFiles = new PriorityQueue<FileInfo, (double, int)>();

            foreach (var (file, i) in files.Select((file, i) => ( file, i )))
            {
                double ttlProg = CalculateTTLProgression(file);
                sortedFiles.Enqueue(file, (-ttlProg, i));
            }

            _logger.LogInformation("Cleaning up files beyond the cache size limit of {cacheSizeLimit} GiB", sizeLimit);
            var totalCacheSizeInBytes = files.Sum(s => s.Length);
            long cacheSizeLimitInBytes = (long)ByteSize.FromGibiBytes(sizeLimit).Bytes;
            while (totalCacheSizeInBytes > cacheSizeLimitInBytes && sortedFiles.Count != 0 && !ct.IsCancellationRequested)
            {
                var file = sortedFiles.Dequeue();
                totalCacheSizeInBytes -= file.Length;
                _logger.LogInformation("Deleting {file} with size {size:N2}MiB", file.FullName, ByteSize.FromBytes(file.Length).MebiBytes);
                file.Delete();
                removedFiles.Add(file.Name);
            }
            files.RemoveAll(f => removedFiles.Contains(f.Name, StringComparer.InvariantCultureIgnoreCase));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error during cache size limit cleanup");
        }

        return removedFiles;
    }

    private void CleanUpOrphanedFiles(HashSet<string> allDbFileHashes, List<FileInfo> allPhysicalFiles, CancellationToken ct)
    {
        // To avoid race conditions with file uploads, only delete files on a second pass
        var newOrphanedFiles = new HashSet<string>(StringComparer.Ordinal);

        foreach (var file in allPhysicalFiles.ToList())
        {
            if (!allDbFileHashes.Contains(file.Name.ToUpperInvariant()))
            {
                _logger.LogInformation("File not in DB, marking: {fileName}", file.Name);
                newOrphanedFiles.Add(file.FullName);
            }

            ct.ThrowIfCancellationRequested();
        }

        foreach (var fullName in _orphanedFiles.Where(f => newOrphanedFiles.Contains(f)))
        {
            var name = Path.GetFileName(fullName);
            File.Delete(fullName);
            _logger.LogInformation("File still not in DB, deleting: {fileName}", name);
            allPhysicalFiles.RemoveAll(f => f.FullName.Equals(fullName, StringComparison.InvariantCultureIgnoreCase));
        }

        _orphanedFiles = newOrphanedFiles;
    }

    private List<string> CleanUpOutdatedFiles(List<FileInfo> files, int unusedRetention, int forcedDeletionAfterHours, CancellationToken ct)
    {
        var removedFiles = new List<string>();
        try
        {
            _logger.LogInformation("Cleaning up files older than {filesOlderThanDays} days", unusedRetention);
            if (forcedDeletionAfterHours > 0)
            {
                _logger.LogInformation("Cleaning up files written to longer than {hours}h ago", forcedDeletionAfterHours);
            }

            var lastAccessCutoffTime = DateTime.Now.Subtract(TimeSpan.FromDays(unusedRetention));
            var forcedDeletionCutoffTime = DateTime.Now.Subtract(TimeSpan.FromHours(forcedDeletionAfterHours));

            foreach (var file in files)
            {
                if (file.LastAccessTime < lastAccessCutoffTime)
                {
                    _logger.LogInformation("File outdated: {fileName}, {fileSize:N2}MiB", file.Name, ByteSize.FromBytes(file.Length).MebiBytes);
                    file.Delete();
                    removedFiles.Add(file.Name);
                }
                else if (forcedDeletionAfterHours > 0 && file.LastWriteTime < forcedDeletionCutoffTime)
                {
                    _logger.LogInformation("File forcefully deleted: {fileName}, {fileSize:N2}MiB", file.Name, ByteSize.FromBytes(file.Length).MebiBytes);
                    file.Delete();
                    removedFiles.Add(file.Name);
                }

                ct.ThrowIfCancellationRequested();
            }
            files.RemoveAll(f => removedFiles.Contains(f.Name, StringComparer.InvariantCultureIgnoreCase));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error during file cleanup of old files");
        }

        return removedFiles;
    }

    private void CleanUpTempFiles()
    {
        var pastTime = DateTime.UtcNow.Subtract(TimeSpan.FromMinutes(20));
        var tempFiles = GetTempFiles();
        foreach (var tempFile in tempFiles.Where(f => f.LastWriteTimeUtc < pastTime))
            tempFile.Delete();
    }

    private async Task CleanUpTask(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var scope = _services.CreateScope();
                using var dbContext = _isMain ? scope.ServiceProvider.GetService<MareDbContext>()! : null;

                HashSet<string> allDbFileHashes = null;

                // Database operations only performed on main server
                if (_isMain)
                {
                    var allDbFiles = await dbContext.Files.ToListAsync(ct).ConfigureAwait(false);
                    allDbFileHashes = new HashSet<string>(allDbFiles.Select(a => a.Hash.ToUpperInvariant()), StringComparer.Ordinal);
                }

                if (_useColdStorage)
                {
                    var coldFiles = GetAllColdFiles();
                    var removedColdFiles = new List<string>();

                    removedColdFiles.AddRange(
                        CleanUpOutdatedFiles(coldFiles, ColdStorageRetention, ForcedDeletionAfterHours, ct)
                    );
                    removedColdFiles.AddRange(
                        CleanUpFilesBeyondSizeLimit(coldFiles, ColdStorageSize, ColdStorageMinimumRetention, ColdStorageRetention, ct)
                    );

                    // Remove cold storage files are deleted from the database, if we are the main file server
                    if (_isMain)
                    {
                        dbContext.Files.RemoveRange(
                            dbContext.Files.Where(f => removedColdFiles.Contains(f.Hash))
                        );
                        allDbFileHashes.ExceptWith(removedColdFiles);
                        CleanUpOrphanedFiles(allDbFileHashes, coldFiles, ct);
                    }

                    // Remove hot copies of files now that the authoritative copy is gone
                    foreach (var removedFile in removedColdFiles)
                    {
                        var hotFile = FilePathUtil.GetFileInfoForHash(_hotStoragePath, removedFile);
                        hotFile?.Delete();
                    }

                    _metrics.SetGaugeTo(MetricsAPI.GaugeFilesTotalSizeColdStorage, coldFiles.Sum(f => { try { return f.Length; } catch { return 0; } }));
                    _metrics.SetGaugeTo(MetricsAPI.GaugeFilesTotalColdStorage, coldFiles.Count);
                }

                var hotFiles = GetAllHotFiles();
                var removedHotFiles = new List<string>();

                removedHotFiles.AddRange(
                    CleanUpOutdatedFiles(hotFiles, HotStorageRetention, forcedDeletionAfterHours: _useColdStorage ? ForcedDeletionAfterHours : -1, ct)
                );
                removedHotFiles.AddRange(
                    CleanUpFilesBeyondSizeLimit(hotFiles, HotStorageSize, HotStorageMinimumRetention, HotStorageRetention, ct)
                );

                if (_isMain)
                {
                    // If cold storage is not active, then "hot" files are deleted from the database instead
                    if (!_useColdStorage)
                    {
                        dbContext.Files.RemoveRange(
                            dbContext.Files.Where(f => removedHotFiles.Contains(f.Hash))
                        );
                        allDbFileHashes.ExceptWith(removedHotFiles);
                    }

                    CleanUpOrphanedFiles(allDbFileHashes, hotFiles, ct);

                    await dbContext.SaveChangesAsync(ct).ConfigureAwait(false);
                }

                _metrics.SetGaugeTo(MetricsAPI.GaugeFilesTotalSize, hotFiles.Sum(f => { try { return f.Length; } catch { return 0; } }));
                _metrics.SetGaugeTo(MetricsAPI.GaugeFilesTotal, hotFiles.Count);

                CleanUpTempFiles();
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error during cleanup task");
            }

            var cleanupCheckMinutes = CleanupCheckMinutes;
            var now = DateTime.Now;
            TimeOnly currentTime = new(now.Hour, now.Minute, now.Second);
            TimeOnly futureTime = new(now.Hour, now.Minute - now.Minute % cleanupCheckMinutes, 0);
            var span = futureTime.AddMinutes(cleanupCheckMinutes) - currentTime;

            _logger.LogInformation("File Cleanup Complete, next run at {date}", now.Add(span));
            await Task.Delay(span, ct).ConfigureAwait(false);
        }
    }

    private void InitializeGauges()
    {
        if (_useColdStorage)
        {
            var allFilesInColdStorageDir = GetAllColdFiles();

            _metrics.SetGaugeTo(MetricsAPI.GaugeFilesTotalSizeColdStorage, allFilesInColdStorageDir.Sum(f => f.Length));
            _metrics.SetGaugeTo(MetricsAPI.GaugeFilesTotalColdStorage, allFilesInColdStorageDir.Count);
        }

        var allFilesInHotStorage = GetAllHotFiles();

        _metrics.SetGaugeTo(MetricsAPI.GaugeFilesTotalSize, allFilesInHotStorage.Sum(f => { try { return f.Length; } catch { return 0; } }));
        _metrics.SetGaugeTo(MetricsAPI.GaugeFilesTotal, allFilesInHotStorage.Count);
    }
}