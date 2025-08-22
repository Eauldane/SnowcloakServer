using MareSynchronos.API.Routes;
using MareSynchronos.API.SignalR;
using MareSynchronosServer.Hubs;
using MareSynchronosServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;

namespace MareSynchronosServer.Controllers;

[Route(MareFiles.Main)]
public class MainController : Controller
{
    private IHubContext<MareHub, IMareHub> _hubContext;

    public MainController(ILogger<MainController> logger, IHubContext<MareHub, IMareHub> hubContext)
    {
        _hubContext = hubContext;
    }

    [HttpGet(MareFiles.Main_SendReady)]
    [Authorize(Policy = "Internal")]
    public IActionResult SendReadyToClients(string uid, Guid requestId)
    {
        _ = Task.Run(async () =>
        {
            await _hubContext.Clients.User(uid).Client_DownloadReady(requestId);
        });
        return Ok();
    }
}