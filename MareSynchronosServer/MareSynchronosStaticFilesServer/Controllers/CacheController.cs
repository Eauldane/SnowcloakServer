using MareSynchronos.API.Routes;
using MareSynchronosStaticFilesServer.Services;
using MareSynchronosStaticFilesServer.Utils;
using Microsoft.AspNetCore.Mvc;
using System.Globalization;
using System.Text;

namespace MareSynchronosStaticFilesServer.Controllers;

[Route(MareFiles.Cache)]
public class CacheController : ControllerBase
{
    private readonly RequestBlockFileListResultFactory _requestBlockFileListResultFactory;
    private readonly CachedFileProvider _cachedFileProvider;
    private readonly RequestQueueService _requestQueue;
    private readonly FileStatisticsService _fileStatisticsService;

    public CacheController(ILogger<CacheController> logger, RequestBlockFileListResultFactory requestBlockFileListResultFactory,
        CachedFileProvider cachedFileProvider, RequestQueueService requestQueue, FileStatisticsService fileStatisticsService) : base(logger)
    {
        _requestBlockFileListResultFactory = requestBlockFileListResultFactory;
        _cachedFileProvider = cachedFileProvider;
        _requestQueue = requestQueue;
        _fileStatisticsService = fileStatisticsService;
    }

    [HttpGet(MareFiles.Cache_Get)]
    public async Task<IActionResult> GetFiles(Guid requestId)
    {
        _logger.LogDebug($"GetFile:{MareUser}:{requestId}");

        if (!_requestQueue.IsActiveProcessing(requestId, MareUser, out var request)) return BadRequest();

        _requestQueue.ActivateRequest(requestId);

        long requestSize = 0;
        var fileList = new List<FileInfo>(request.FileIds.Count);

        foreach (var file in request.FileIds)
        {
            var fi = await _cachedFileProvider.GetAndDownloadFile(file);
            if (fi == null) continue;
            requestSize += fi.Length;
            fileList.Add(fi);
        }

        _fileStatisticsService.LogRequest(requestSize);

        return _requestBlockFileListResultFactory.Create(requestId, fileList);
    }
}
