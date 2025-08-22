using MareSynchronos.API.Data;
using MareSynchronos.API.Data.Enum;
using MareSynchronos.API.Dto.Group;
using MareSynchronos.API.Dto.User;
using MareSynchronosServer.Utils;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;

namespace MareSynchronosServer.Hubs;

public partial class MareHub
{
    [Authorize(Policy = "Identified")]
    public Task UserChatSendMsg(UserDto dto, ChatMessage message)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));
        // TODO
        return Task.CompletedTask;
    }

    [Authorize(Policy = "Identified")]
    public async Task GroupChatSendMsg(GroupDto dto, ChatMessage message)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));

        var (userExists, groupPair) = await TryValidateUserInGroup(dto.GID, UserUID).ConfigureAwait(false);
        if (!userExists) return;

        var group = await DbContext.Groups.AsNoTracking().SingleAsync(g => g.GID == dto.GID).ConfigureAwait(false);
        var sender = await DbContext.Users.AsNoTracking().SingleAsync(u => u.UID == UserUID).ConfigureAwait(false);
        var groupPairs = await DbContext.GroupPairs.AsNoTracking().Include(p => p.GroupUser).Where(p => p.GroupGID == dto.Group.GID).ToListAsync().ConfigureAwait(false);

        if (group == null || sender == null) return;

        // TODO: Add and check chat permissions
        if (group.Alias?.Equals("Snowcloak", StringComparison.Ordinal) ?? false)
        {
            await Clients.Caller.Client_ReceiveServerMessage(MessageSeverity.Warning, $"Chat is disabled for syncshell '{dto.GroupAliasOrGID}'.").ConfigureAwait(false);
            return;
        }

        // TOOO: Sign the message
        var signedMessage = new SignedChatMessage(message, sender.ToUserData())
        {
            Timestamp = 0,
            Signature = "",
        };

        await Clients.Users(groupPairs.Select(p => p.GroupUserUID)).Client_GroupChatMsg(new(new(group.ToGroupData()), signedMessage)).ConfigureAwait(false);
    }
}
