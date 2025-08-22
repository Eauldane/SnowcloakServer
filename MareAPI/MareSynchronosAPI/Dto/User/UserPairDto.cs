using MareSynchronos.API.Data;
using MareSynchronos.API.Data.Enum;
using MessagePack;

namespace MareSynchronos.API.Dto.User;

[MessagePackObject(keyAsPropertyName: true)]
public record UserPairDto(UserData User, UserPermissions OwnPermissions, UserPermissions OtherPermissions) : UserDto(User)
{
    public UserPermissions OwnPermissions { get; set; } = OwnPermissions;
    public UserPermissions OtherPermissions { get; set; } = OtherPermissions;
}