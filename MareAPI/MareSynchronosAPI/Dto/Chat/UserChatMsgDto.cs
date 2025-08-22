using MareSynchronos.API.Data;
using MareSynchronos.API.Dto.User;
using MessagePack;

namespace MareSynchronos.API.Dto.Chat;

[MessagePackObject(keyAsPropertyName: true)]
public record UserChatMsgDto(SignedChatMessage Message)
{
    public SignedChatMessage Message = Message;
}