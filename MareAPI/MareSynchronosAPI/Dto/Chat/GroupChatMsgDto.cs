using MareSynchronos.API.Data;
using MareSynchronos.API.Dto.Group;
using MareSynchronos.API.Dto.User;
using MessagePack;

namespace MareSynchronos.API.Dto.Chat;

[MessagePackObject(keyAsPropertyName: true)]
public record GroupChatMsgDto(GroupDto Group, SignedChatMessage Message)
{
    public GroupDto Group = Group;
    public SignedChatMessage Message = Message;
}