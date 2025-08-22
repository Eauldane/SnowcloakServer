using MareSynchronosShared.Metrics;
using MareSynchronosShared.Services;
using MareSynchronosShared.Utils.Configuration;
using MareSynchronosStaticFilesServer.Services;
using Microsoft.AspNetCore.Mvc;
using System.Globalization;
using System.Text;

namespace MareSynchronosStaticFilesServer.Utils;

public class RequestBlockFileListResult : IActionResult
{
    private readonly Guid _requestId;
    private readonly RequestQueueService _requestQueueService;
    private readonly MareMetrics _mareMetrics;
    private readonly IEnumerable<FileInfo> _fileList;
    private readonly IConfigurationService<StaticFilesServerConfiguration> _configurationService;

    public RequestBlockFileListResult(Guid requestId, RequestQueueService requestQueueService, MareMetrics mareMetrics, IEnumerable<FileInfo> fileList,
        IConfigurationService<StaticFilesServerConfiguration> configurationService)
    {
        _requestId = requestId;
        _requestQueueService = requestQueueService;
        _mareMetrics = mareMetrics;
        _mareMetrics.IncGauge(MetricsAPI.GaugeCurrentDownloads);
        _fileList = fileList;
        _configurationService = configurationService;
    }

    public async Task ExecuteResultAsync(ActionContext context)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(context);

            var useSSI = _configurationService.GetValueOrDefault(nameof(StaticFilesServerConfiguration.UseSSI), false);

            context.HttpContext.Response.StatusCode = 200;

            if (useSSI)
                context.HttpContext.Response.ContentType = _configurationService.GetValue<string>(nameof(StaticFilesServerConfiguration.SSIContentType));
            else
                context.HttpContext.Response.ContentType = "application/octet-stream";

            string ssiFilePrefix = null;

            if (useSSI)
                ssiFilePrefix = _configurationService.GetValue<string>(nameof(StaticFilesServerConfiguration.XAccelRedirectPrefix));

            foreach (var file in _fileList)
            {
                if (useSSI)
                {
                    var internalName = Path.Combine(ssiFilePrefix, file.Name);
                    await context.HttpContext.Response.WriteAsync(
                        "#" + file.Name + ":" + file.Length.ToString(CultureInfo.InvariantCulture) + "#"
                        + "<!--#include file=\"" + internalName + "\" -->", Encoding.ASCII);
                }
                else
                {
                    await context.HttpContext.Response.WriteAsync("#" + file.Name + ":" + file.Length.ToString(CultureInfo.InvariantCulture) + "#", Encoding.ASCII);
                    await context.HttpContext.Response.SendFileAsync(file.FullName);
                }
            }
        }
        catch
        {
            throw;
        }
        finally
        {
            _requestQueueService.FinishRequest(_requestId);
            _mareMetrics.DecGauge(MetricsAPI.GaugeCurrentDownloads);
        }
    }
}