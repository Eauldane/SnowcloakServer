using MareSynchronosShared.Utils;
using System.Text;

namespace MareSynchronosShared.Utils.Configuration;

public class StaticFilesServerConfiguration : MareConfigurationBase
{
    public bool IsDistributionNode { get; set; } = false;
    public bool NotifyMainServerDirectly { get; set; } = false;
    public Uri MainFileServerAddress { get; set; } = null;
    public Uri DistributionFileServerAddress { get; set; } = null;
    public bool DistributionFileServerForceHTTP2 { get; set; } = false;
    public int ForcedDeletionOfFilesAfterHours { get; set; } = -1;
    public double CacheSizeHardLimitInGiB { get; set; } = -1;
    public int MinimumFileRetentionPeriodInDays { get; set; } = 7;
    public int UnusedFileRetentionPeriodInDays { get; set; } = 14;
    public string CacheDirectory { get; set; }
    public int DownloadQueueSize { get; set; } = 50;
    public int DownloadTimeoutSeconds { get; set; } = 5;
    public int DownloadQueueReleaseSeconds { get; set; } = 15;
    public int DownloadQueueClearLimit { get; set; } = 15000;
    public int CleanupCheckInMinutes { get; set; } = 15;
    public bool UseColdStorage { get; set; } = false;
    public string ColdStorageDirectory { get; set; } = null;
    public double ColdStorageSizeHardLimitInGiB { get; set; } = -1;
    public int ColdStorageMinimumFileRetentionPeriodInDays { get; set; } = 30;
    public int ColdStorageUnusedFileRetentionPeriodInDays { get; set; } = 30;
    public double CacheSmallSizeThresholdKiB { get; set; } = 64;
    public double CacheLargeSizeThresholdKiB { get; set; } = 1024;
    [RemoteConfiguration]
    public Uri CdnFullUrl { get; set; } = null;
    [RemoteConfiguration]
    public List<CdnShardConfiguration> CdnShardConfiguration { get; set; } = new();

    public bool UseXAccelRedirect { get; set; } = false;
    public string XAccelRedirectPrefix { get; set; } = "/_internal/mare-files/";
    public bool UseSSI { get; set; } = false;
    public string SSIContentType { get; set; } = "application/x-block-file-list";

    public override string ToString()
    {
        StringBuilder sb = new();
        sb.AppendLine(base.ToString());
        sb.AppendLine($"{nameof(IsDistributionNode)} => {IsDistributionNode}");
        sb.AppendLine($"{nameof(NotifyMainServerDirectly)} => {NotifyMainServerDirectly}");
        sb.AppendLine($"{nameof(MainFileServerAddress)} => {MainFileServerAddress}");
        sb.AppendLine($"{nameof(DistributionFileServerAddress)} => {DistributionFileServerAddress}");
        sb.AppendLine($"{nameof(DistributionFileServerForceHTTP2)} => {DistributionFileServerForceHTTP2}");
        sb.AppendLine($"{nameof(ForcedDeletionOfFilesAfterHours)} => {ForcedDeletionOfFilesAfterHours}");
        sb.AppendLine($"{nameof(CacheSizeHardLimitInGiB)} => {CacheSizeHardLimitInGiB}");
        sb.AppendLine($"{nameof(UseColdStorage)} => {UseColdStorage}");
        sb.AppendLine($"{nameof(ColdStorageDirectory)} => {ColdStorageDirectory}");
        sb.AppendLine($"{nameof(ColdStorageSizeHardLimitInGiB)} => {ColdStorageSizeHardLimitInGiB}");
        sb.AppendLine($"{nameof(ColdStorageMinimumFileRetentionPeriodInDays)} => {ColdStorageMinimumFileRetentionPeriodInDays}");
        sb.AppendLine($"{nameof(ColdStorageUnusedFileRetentionPeriodInDays)} => {ColdStorageUnusedFileRetentionPeriodInDays}");
        sb.AppendLine($"{nameof(MinimumFileRetentionPeriodInDays)} => {MinimumFileRetentionPeriodInDays}");
        sb.AppendLine($"{nameof(UnusedFileRetentionPeriodInDays)} => {UnusedFileRetentionPeriodInDays}");
        sb.AppendLine($"{nameof(CacheSmallSizeThresholdKiB)} => {CacheSmallSizeThresholdKiB}");
        sb.AppendLine($"{nameof(CacheLargeSizeThresholdKiB)} => {CacheLargeSizeThresholdKiB}");
        sb.AppendLine($"{nameof(CacheDirectory)} => {CacheDirectory}");
        sb.AppendLine($"{nameof(DownloadQueueSize)} => {DownloadQueueSize}");
        sb.AppendLine($"{nameof(DownloadQueueReleaseSeconds)} => {DownloadQueueReleaseSeconds}");
        sb.AppendLine($"{nameof(CdnShardConfiguration)} => {string.Join(", ", CdnShardConfiguration)}");
        sb.AppendLine($"{nameof(UseXAccelRedirect)} => {UseXAccelRedirect}");
        return sb.ToString();
    }
}
