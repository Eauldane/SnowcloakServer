using MareSynchronos.API.Data;
using MessagePack;

namespace MareSynchronos.API.Dto.Group;

[MessagePackObject(keyAsPropertyName: true)]
public record GroupPasswordDto(GroupData Group, string Password) : GroupDto(Group);
