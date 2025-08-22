using System.Text;

namespace MareSynchronosShared.Utils.Configuration;

public class AuthServiceConfiguration : MareConfigurationBase
{
    public string GeoIPDbCityFile { get; set; } = string.Empty;
    public bool UseGeoIP { get; set; } = false;
    public int FailedAuthForTempBan { get; set; } = 5;
    public int TempBanDurationInMinutes { get; set; } = 5;
    public List<string> WhitelistedIps { get; set; } = new();

    public int RegisterIpLimit { get; set; } = 3;
    public int RegisterIpDurationInMinutes { get; set; } = 10;

    public string WellKnown { get; set; } = string.Empty;

    public override string ToString()
    {
        StringBuilder sb = new();
        sb.AppendLine(base.ToString());
        sb.AppendLine($"{nameof(GeoIPDbCityFile)} => {GeoIPDbCityFile}");
        sb.AppendLine($"{nameof(UseGeoIP)} => {UseGeoIP}");
        sb.AppendLine($"{nameof(RegisterIpLimit)} => {RegisterIpLimit}");
        sb.AppendLine($"{nameof(RegisterIpDurationInMinutes)} => {RegisterIpDurationInMinutes}");
        sb.AppendLine($"{nameof(WellKnown)} => {WellKnown}");
        return sb.ToString();
    }
}
