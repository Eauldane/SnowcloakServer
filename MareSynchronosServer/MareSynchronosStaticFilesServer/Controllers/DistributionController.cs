using MareSynchronos.API.Routes;
using MareSynchronosShared.Services;
using MareSynchronosShared.Utils.Configuration;
using MareSynchronosStaticFilesServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MareSynchronosStaticFilesServer.Controllers;

[Route(MareFiles.Distribution)]
public class DistributionController : ControllerBase
{
    private readonly CachedFileProvider _cachedFileProvider;
    private readonly IConfigurationService<StaticFilesServerConfiguration> _configuration;

    public DistributionController(ILogger<DistributionController> logger, CachedFileProvider cachedFileProvider,
        IConfigurationService<StaticFilesServerConfiguration> configuration) : base(logger)
    {
        _cachedFileProvider = cachedFileProvider;
        _configuration = configuration;
    }

    [HttpGet(MareFiles.Distribution_Get)]
    [Authorize(Policy = "Internal")]
    public async Task<IActionResult> GetFile(string file)
    {
        _logger.LogInformation($"GetFile:{MareUser}:{file}");

        var fi = await _cachedFileProvider.GetAndDownloadFile(file);
        if (fi == null) return NotFound();

        if (_configuration.GetValueOrDefault(nameof(StaticFilesServerConfiguration.UseXAccelRedirect), false))
        {
            var prefix = _configuration.GetValue<string>(nameof(StaticFilesServerConfiguration.XAccelRedirectPrefix));
            Response.Headers.Append("X-Accel-Redirect", Path.Combine(prefix, file));
            return Ok();
        }
        else
        {
            return PhysicalFile(fi.FullName, "application/octet-stream");
        }
    }

    [HttpPost("touch")]
    [Authorize(Policy = "Internal")]
    public IActionResult TouchFiles([FromBody] string[] files)
    {
        _logger.LogInformation($"TouchFiles:{MareUser}:{files.Length}");

        if (files.Length == 0)
            return Ok();

        Task.Run(() => {
            foreach (var file in files)
                _cachedFileProvider.TouchColdHash(file);
        }).ConfigureAwait(false);

        return Ok();
    }
}
