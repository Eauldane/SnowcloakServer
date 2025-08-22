using MareSynchronos.API.Data;
using MareSynchronos.API.Data.Enum;
using MessagePack;

namespace MareSynchronos.API.Dto.Group;

[MessagePackObject(keyAsPropertyName: true)]
public record GroupPairUserInfoDto(GroupData Group, UserData User, GroupUserInfo GroupUserInfo) : GroupPairDto(Group, User);
