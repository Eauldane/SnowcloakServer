using MareSynchronosShared.Metrics;
using MareSynchronosShared.Services;
using MareSynchronosShared.Utils.Configuration;
using MareSynchronosStaticFilesServer.Services;

namespace MareSynchronosStaticFilesServer.Utils;

public class RequestBlockFileListResultFactory
{
    private readonly MareMetrics _metrics;
    private readonly RequestQueueService _requestQueueService;
    private readonly IConfigurationService<StaticFilesServerConfiguration> _configurationService;

    public RequestBlockFileListResultFactory(MareMetrics metrics, RequestQueueService requestQueueService, IConfigurationService<StaticFilesServerConfiguration> configurationService)
    {
        _metrics = metrics;
        _requestQueueService = requestQueueService;
        _configurationService = configurationService;
    }

    public RequestBlockFileListResult Create(Guid requestId, IEnumerable<FileInfo> fileList)
    {
        return new RequestBlockFileListResult(requestId, _requestQueueService, _metrics, fileList, _configurationService);
    }
}