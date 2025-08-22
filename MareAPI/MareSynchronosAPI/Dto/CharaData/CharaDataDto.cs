using MareSynchronos.API.Data;

namespace MareSynchronos.API.Dto.CharaData;

public record CharaDataDto(string Id, UserData Uploader)
{
    public string Description { get; init; } = string.Empty;
    public DateTime UpdatedDate { get; init; }
}
