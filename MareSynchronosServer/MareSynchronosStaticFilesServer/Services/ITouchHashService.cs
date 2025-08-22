namespace MareSynchronosStaticFilesServer.Services;

public interface ITouchHashService : IHostedService
{
    void TouchColdHash(string hash);
}
