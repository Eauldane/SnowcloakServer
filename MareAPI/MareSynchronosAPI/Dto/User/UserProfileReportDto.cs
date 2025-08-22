using MareSynchronos.API.Data;
using MessagePack;

namespace MareSynchronos.API.Dto.User;

[MessagePackObject(keyAsPropertyName: true)]
public record UserProfileReportDto(UserData User, string ProfileReport) : UserDto(User);