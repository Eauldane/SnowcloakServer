using MareSynchronos.API.Data;
using MareSynchronos.API.Data.Enum;
using MareSynchronos.API.Data.Extensions;
using MareSynchronos.API.Dto.Chat;
using MareSynchronos.API.Dto.Group;
using MareSynchronosServer.Utils;
using MareSynchronosShared.Models;
using MareSynchronosShared.Utils;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace MareSynchronosServer.Hubs;

public partial class MareHub
{
    [Authorize(Policy = "Identified")]
    public async Task GroupBanUser(GroupPairDto dto, string reason)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto, reason));

        var (userHasRights, group) = await TryValidateGroupModeratorOrOwner(dto.Group.GID).ConfigureAwait(false);
        if (!userHasRights) return;

        var (userExists, groupPair) = await TryValidateUserInGroup(dto.Group.GID, dto.User.UID).ConfigureAwait(false);
        if (!userExists) return;

        if (groupPair.IsModerator || string.Equals(group.OwnerUID, dto.User.UID, StringComparison.Ordinal)) return;

        var alias = string.IsNullOrEmpty(groupPair.GroupUser.Alias) ? "-" : groupPair.GroupUser.Alias;
        var ban = new GroupBan()
        {
            BannedByUID = UserUID,
            BannedReason = $"{reason} (Alias at time of ban: {alias})",
            BannedOn = DateTime.UtcNow,
            BannedUserUID = dto.User.UID,
            GroupGID = dto.Group.GID,
        };

        DbContext.Add(ban);
        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        await GroupRemoveUser(dto).ConfigureAwait(false);

        _logger.LogCallInfo(MareHubLogger.Args(dto, "Success"));
    }

    [Authorize(Policy = "Identified")]
    public async Task GroupChangeGroupPermissionState(GroupPermissionDto dto)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));

        var (hasRights, group) = await TryValidateGroupModeratorOrOwner(dto.Group.GID).ConfigureAwait(false);
        if (!hasRights) return;

        group.InvitesEnabled = !dto.Permissions.HasFlag(GroupPermissions.DisableInvites);
        group.DisableSounds = dto.Permissions.HasFlag(GroupPermissions.DisableSounds);
        group.DisableAnimations = dto.Permissions.HasFlag(GroupPermissions.DisableAnimations);
        group.DisableVFX = dto.Permissions.HasFlag(GroupPermissions.DisableVFX);

        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        var groupPairs = DbContext.GroupPairs.Where(p => p.GroupGID == dto.Group.GID).Select(p => p.GroupUserUID).ToList();
        await Clients.Users(groupPairs).Client_GroupChangePermissions(new GroupPermissionDto(dto.Group, dto.Permissions)).ConfigureAwait(false);
    }

    [Authorize(Policy = "Identified")]
    public async Task GroupChangeIndividualPermissionState(GroupPairUserPermissionDto dto)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));

        var (inGroup, groupPair) = await TryValidateUserInGroup(dto.Group.GID).ConfigureAwait(false);
        if (!inGroup) return;

        var wasPaused = groupPair.IsPaused;
        groupPair.DisableSounds = dto.GroupPairPermissions.IsDisableSounds();
        groupPair.DisableAnimations = dto.GroupPairPermissions.IsDisableAnimations();
        groupPair.IsPaused = dto.GroupPairPermissions.IsPaused();
        groupPair.DisableVFX = dto.GroupPairPermissions.IsDisableVFX();

        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        var groupPairs = DbContext.GroupPairs.Include(p => p.GroupUser).Where(p => p.GroupGID == dto.Group.GID).ToList();
        await Clients.Users(groupPairs.Select(p => p.GroupUserUID)).Client_GroupPairChangePermissions(dto).ConfigureAwait(false);

        var allUserPairs = await GetAllPairedClientsWithPauseState().ConfigureAwait(false);
        var self = await DbContext.Users.SingleAsync(u => u.UID == UserUID).ConfigureAwait(false);

        if (wasPaused == groupPair.IsPaused) return;

        foreach (var groupUserPair in groupPairs.Where(u => !string.Equals(u.GroupUserUID, UserUID, StringComparison.Ordinal)).ToList())
        {
            var userPair = allUserPairs.SingleOrDefault(p => string.Equals(p.UID, groupUserPair.GroupUserUID, StringComparison.Ordinal));
            if (userPair != null)
            {
                if (userPair.IsDirectlyPaused != PauseInfo.NoConnection) continue;
                if (userPair.IsPausedExcludingGroup(dto.Group.GID) is PauseInfo.Unpaused) continue;
                if (userPair.IsOtherPausedForSpecificGroup(dto.Group.GID) is PauseInfo.Paused) continue;
            }

            var groupUserIdent = await GetUserIdent(groupUserPair.GroupUserUID).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(groupUserIdent))
            {
                if (!groupPair.IsPaused)
                {
                    await Clients.User(UserUID).Client_UserSendOnline(new(groupUserPair.ToUserData(), groupUserIdent)).ConfigureAwait(false);
                    await Clients.User(groupUserPair.GroupUserUID)
                        .Client_UserSendOnline(new(self.ToUserData(), UserCharaIdent)).ConfigureAwait(false);
                }
                else
                {
                    await Clients.User(UserUID).Client_UserSendOffline(new(groupUserPair.ToUserData())).ConfigureAwait(false);
                    await Clients.User(groupUserPair.GroupUserUID)
                        .Client_UserSendOffline(new(self.ToUserData())).ConfigureAwait(false);
                }
            }
        }
    }

    [Authorize(Policy = "Identified")]
    public async Task GroupChangeOwnership(GroupPairDto dto)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));

        var (isOwner, group) = await TryValidateOwner(dto.Group.GID).ConfigureAwait(false);
        if (!isOwner) return;

        var (isInGroup, newOwnerPair) = await TryValidateUserInGroup(dto.Group.GID, dto.User.UID).ConfigureAwait(false);
        if (!isInGroup) return;

        var ownedShells = await DbContext.Groups.CountAsync(g => g.OwnerUID == dto.User.UID).ConfigureAwait(false);
        if (ownedShells >= _maxExistingGroupsByUser) return;

        var prevOwner = await DbContext.GroupPairs.SingleOrDefaultAsync(g => g.GroupGID == dto.Group.GID && g.GroupUserUID == UserUID).ConfigureAwait(false);
        prevOwner.IsPinned = false;
        group.Owner = newOwnerPair.GroupUser;
        group.Alias = null;
        newOwnerPair.IsPinned = true;
        newOwnerPair.IsModerator = false;
        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        _logger.LogCallInfo(MareHubLogger.Args(dto, "Success"));

        var groupPairs = await DbContext.GroupPairs.Where(p => p.GroupGID == dto.Group.GID).Select(p => p.GroupUserUID).AsNoTracking().ToListAsync().ConfigureAwait(false);

        await Clients.Users(groupPairs).Client_GroupSendInfo(new GroupInfoDto(group.ToGroupData(), newOwnerPair.GroupUser.ToUserData(), group.GetGroupPermissions())).ConfigureAwait(false);
    }

    [Authorize(Policy = "Identified")]
    public async Task<bool> GroupChangePassword(GroupPasswordDto dto)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));

        var (isOwner, group) = await TryValidateOwner(dto.Group.GID).ConfigureAwait(false);
        if (!isOwner || dto.Password.Length < 10) return false;

        _logger.LogCallInfo(MareHubLogger.Args(dto, "Success"));

        group.HashedPassword = StringUtils.Sha256String(dto.Password);
        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        return true;
    }

    [Authorize(Policy = "Identified")]
    public async Task GroupClear(GroupDto dto)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));

        var (hasRights, group) = await TryValidateGroupModeratorOrOwner(dto.Group.GID).ConfigureAwait(false);
        if (!hasRights) return;

        var groupPairs = await DbContext.GroupPairs.Include(p => p.GroupUser).Where(p => p.GroupGID == dto.Group.GID).ToListAsync().ConfigureAwait(false);

        await Clients.Users(groupPairs.Where(p => !p.IsPinned && !p.IsModerator).Select(g => g.GroupUserUID)).Client_GroupDelete(new GroupDto(group.ToGroupData())).ConfigureAwait(false);

        _logger.LogCallInfo(MareHubLogger.Args(dto, "Success"));

        var notPinned = groupPairs.Where(g => !g.IsPinned && !g.IsModerator).ToList();

        DbContext.GroupPairs.RemoveRange(notPinned);
        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        foreach (var pair in notPinned)
        {
            await Clients.Users(groupPairs.Where(p => p.IsPinned).Select(g => g.GroupUserUID)).Client_GroupPairLeft(new GroupPairDto(dto.Group, pair.GroupUser.ToUserData())).ConfigureAwait(false);

            var pairIdent = await GetUserIdent(pair.GroupUserUID).ConfigureAwait(false);
            if (string.IsNullOrEmpty(pairIdent)) continue;

            var allUserPairs = await GetAllPairedClientsWithPauseState(pair.GroupUserUID).ConfigureAwait(false);

            var sharedData = await DbContext.CharaDataAllowances.Where(u => u.AllowedGroup != null && u.AllowedGroupGID == dto.GID && u.ParentUploaderUID == pair.GroupUserUID).ToListAsync().ConfigureAwait(false);
            DbContext.CharaDataAllowances.RemoveRange(sharedData);

            foreach (var groupUserPair in groupPairs.Where(p => !string.Equals(p.GroupUserUID, pair.GroupUserUID, StringComparison.Ordinal)))
            {
                await UserGroupLeave(groupUserPair, allUserPairs, pairIdent).ConfigureAwait(false);
            }
        }
    }

    [Authorize(Policy = "Identified")]
    public async Task<GroupPasswordDto> GroupCreate()
    {
        _logger.LogCallInfo();
        var existingGroupsByUser = await DbContext.Groups.CountAsync(u => u.OwnerUID == UserUID).ConfigureAwait(false);
        var existingJoinedGroups = await DbContext.GroupPairs.CountAsync(u => u.GroupUserUID == UserUID).ConfigureAwait(false);
        if (existingGroupsByUser >= _maxExistingGroupsByUser || existingJoinedGroups >= _maxJoinedGroupsByUser)
        {
            throw new System.Exception($"Max groups for user is {_maxExistingGroupsByUser}, max joined groups is {_maxJoinedGroupsByUser}.");
        }

        var gid = StringUtils.GenerateRandomString(9);
        while (await DbContext.Groups.AnyAsync(g => g.GID == "SNOW-" + gid).ConfigureAwait(false))
        {
            gid = StringUtils.GenerateRandomString(9);
        }
        gid = "SNOW-" + gid;

        var passwd = StringUtils.GenerateRandomString(16);
        var sha = SHA256.Create();
        var hashedPw = StringUtils.Sha256String(passwd);

        Group newGroup = new()
        {
            GID = gid,
            HashedPassword = hashedPw,
            InvitesEnabled = true,
            OwnerUID = UserUID,
        };

        GroupPair initialPair = new()
        {
            GroupGID = newGroup.GID,
            GroupUserUID = UserUID,
            IsPaused = false,
            IsPinned = true,
        };

        await DbContext.Groups.AddAsync(newGroup).ConfigureAwait(false);
        await DbContext.GroupPairs.AddAsync(initialPair).ConfigureAwait(false);
        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        var self = await DbContext.Users.SingleAsync(u => u.UID == UserUID).ConfigureAwait(false);

        await Clients.User(UserUID).Client_GroupSendFullInfo(new GroupFullInfoDto(newGroup.ToGroupData(), self.ToUserData(), GroupPermissions.NoneSet, GroupUserPermissions.NoneSet, GroupUserInfo.None))
            .ConfigureAwait(false);

        _logger.LogCallInfo(MareHubLogger.Args(gid));

        return new GroupPasswordDto(newGroup.ToGroupData(), passwd);
    }

    [Authorize(Policy = "Identified")]
    public async Task<List<string>> GroupCreateTempInvite(GroupDto dto, int amount)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto, amount));
        List<string> inviteCodes = new();
        List<GroupTempInvite> tempInvites = new();
        var (hasRights, group) = await TryValidateGroupModeratorOrOwner(dto.Group.GID).ConfigureAwait(false);
        if (!hasRights) return new();

        var existingInvites = await DbContext.GroupTempInvites.Where(g => g.GroupGID == group.GID).ToListAsync().ConfigureAwait(false);

        for (int i = 0; i < amount; i++)
        {
            bool hasValidInvite = false;
            string invite = string.Empty;
            string hashedInvite = string.Empty;
            while (!hasValidInvite)
            {
                invite = StringUtils.GenerateRandomString(10, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
                hashedInvite = StringUtils.Sha256String(invite);
                if (existingInvites.Any(i => string.Equals(i.Invite, hashedInvite, StringComparison.Ordinal))) continue;
                hasValidInvite = true;
                inviteCodes.Add(invite);
            }

            tempInvites.Add(new GroupTempInvite()
            {
                ExpirationDate = DateTime.UtcNow.AddDays(1),
                GroupGID = group.GID,
                Invite = hashedInvite,
            });
        }

        DbContext.GroupTempInvites.AddRange(tempInvites);
        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        return inviteCodes;
    }

    [Authorize(Policy = "Identified")]
    public async Task GroupDelete(GroupDto dto)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));

        var (hasRights, group) = await TryValidateOwner(dto.Group.GID).ConfigureAwait(false);

        _logger.LogCallInfo(MareHubLogger.Args(dto, "Success"));

        var groupPairs = await DbContext.GroupPairs.Where(p => p.GroupGID == dto.Group.GID).ToListAsync().ConfigureAwait(false);
        DbContext.RemoveRange(groupPairs);
        DbContext.Remove(group);
        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        await Clients.Users(groupPairs.Select(g => g.GroupUserUID)).Client_GroupDelete(new GroupDto(group.ToGroupData())).ConfigureAwait(false);

        await SendGroupDeletedToAll(groupPairs).ConfigureAwait(false);
    }

    [Authorize(Policy = "Identified")]
    public async Task<List<BannedGroupUserDto>> GroupGetBannedUsers(GroupDto dto)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));

        var (userHasRights, group) = await TryValidateGroupModeratorOrOwner(dto.GID).ConfigureAwait(false);
        if (!userHasRights) return new List<BannedGroupUserDto>();

        var banEntries = await DbContext.GroupBans.Include(b => b.BannedUser).Where(g => g.GroupGID == dto.Group.GID).AsNoTracking().ToListAsync().ConfigureAwait(false);

        List<BannedGroupUserDto> bannedGroupUsers = banEntries.Select(b =>
            new BannedGroupUserDto(group.ToGroupData(), b.BannedUser.ToUserData(), b.BannedReason, b.BannedOn,
                b.BannedByUID)).ToList();

        _logger.LogCallInfo(MareHubLogger.Args(dto, bannedGroupUsers.Count));

        return bannedGroupUsers;
    }

    [Authorize(Policy = "Identified")]
    public async Task<bool> GroupJoin(GroupPasswordDto dto)
    {
        var aliasOrGid = dto.Group.GID.Trim();

        _logger.LogCallInfo(MareHubLogger.Args(dto.Group));

        var group = await DbContext.Groups.Include(g => g.Owner).AsNoTracking().SingleOrDefaultAsync(g => g.GID == aliasOrGid || g.Alias == aliasOrGid).ConfigureAwait(false);
        var groupGid = group?.GID ?? string.Empty;
        var existingPair = await DbContext.GroupPairs.AsNoTracking().SingleOrDefaultAsync(g => g.GroupGID == groupGid && g.GroupUserUID == UserUID).ConfigureAwait(false);
        var hashedPw = StringUtils.Sha256String(dto.Password);
        var existingUserCount = await DbContext.GroupPairs.AsNoTracking().CountAsync(g => g.GroupGID == groupGid).ConfigureAwait(false);
        var joinedGroups = await DbContext.GroupPairs.CountAsync(g => g.GroupUserUID == UserUID).ConfigureAwait(false);
        var isBanned = await DbContext.GroupBans.AnyAsync(g => g.GroupGID == groupGid && g.BannedUserUID == UserUID).ConfigureAwait(false);
        var oneTimeInvite = await DbContext.GroupTempInvites.SingleOrDefaultAsync(g => g.GroupGID == groupGid && g.Invite == hashedPw).ConfigureAwait(false);

        if (group == null
            || (!string.Equals(group.HashedPassword, hashedPw, StringComparison.Ordinal) && oneTimeInvite == null)
            || existingPair != null
            || existingUserCount >= _maxGroupUserCount
            || !group.InvitesEnabled
            || joinedGroups >= _maxJoinedGroupsByUser
            || isBanned)
            return false;

        if (oneTimeInvite != null)
        {
            _logger.LogCallInfo(MareHubLogger.Args(aliasOrGid, "TempInvite", oneTimeInvite.Invite));
            DbContext.Remove(oneTimeInvite);
        }

        GroupPair newPair = new()
        {
            GroupGID = group.GID,
            GroupUserUID = UserUID,
            DisableAnimations = false,
            DisableSounds = false,
            DisableVFX = false
        };

        await DbContext.GroupPairs.AddAsync(newPair).ConfigureAwait(false);
        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        _logger.LogCallInfo(MareHubLogger.Args(aliasOrGid, "Success"));

        await Clients.User(UserUID).Client_GroupSendFullInfo(new GroupFullInfoDto(group.ToGroupData(), group.Owner.ToUserData(), group.GetGroupPermissions(), newPair.GetGroupPairPermissions(), newPair.GetGroupPairUserInfo())).ConfigureAwait(false);

        var self = DbContext.Users.Single(u => u.UID == UserUID);

        var groupPairs = await DbContext.GroupPairs.Include(p => p.GroupUser).Where(p => p.GroupGID == group.GID && p.GroupUserUID != UserUID).ToListAsync().ConfigureAwait(false);

        await Clients.Users(groupPairs.Select(p => p.GroupUserUID))
            .Client_GroupPairJoined(new GroupPairFullInfoDto(group.ToGroupData(), self.ToUserData(), newPair.GetGroupPairUserInfo(), newPair.GetGroupPairPermissions())).ConfigureAwait(false);
        foreach (var pair in groupPairs)
        {
            await Clients.User(UserUID).Client_GroupPairJoined(new GroupPairFullInfoDto(group.ToGroupData(), pair.ToUserData(), pair.GetGroupPairUserInfo(), pair.GetGroupPairPermissions())).ConfigureAwait(false);
        }

        var allUserPairs = await GetAllPairedClientsWithPauseState().ConfigureAwait(false);

        foreach (var groupUserPair in groupPairs)
        {
            var userPair = allUserPairs.Single(p => string.Equals(p.UID, groupUserPair.GroupUserUID, StringComparison.Ordinal));
            if (userPair.IsDirectlyPaused != PauseInfo.NoConnection) continue;
            if (userPair.IsPausedExcludingGroup(group.GID) is PauseInfo.Unpaused) continue;
            if (userPair.IsPausedPerGroup is PauseInfo.Paused) continue;

            var groupUserIdent = await GetUserIdent(groupUserPair.GroupUserUID).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(groupUserIdent))
            {
                await Clients.User(UserUID).Client_UserSendOnline(new(groupUserPair.ToUserData(), groupUserIdent)).ConfigureAwait(false);
                await Clients.User(groupUserPair.GroupUserUID)
                    .Client_UserSendOnline(new(self.ToUserData(), UserCharaIdent)).ConfigureAwait(false);
            }
        }

        return true;
    }

    [Authorize(Policy = "Identified")]
    public async Task GroupLeave(GroupDto dto)
    {
        await UserLeaveGroup(dto, UserUID).ConfigureAwait(false);
    }

    [Authorize(Policy = "Identified")]
    public async Task<int> GroupPrune(GroupDto dto, int days, bool execute)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto, days, execute));

        var (hasRights, group) = await TryValidateGroupModeratorOrOwner(dto.Group.GID).ConfigureAwait(false);
        if (!hasRights) return -1;

        var allGroupUsers = await DbContext.GroupPairs.Include(p => p.GroupUser).Include(p => p.Group)
            .Where(g => g.GroupGID == dto.Group.GID)
            .ToListAsync().ConfigureAwait(false);
        var usersToPrune = allGroupUsers.Where(p => !p.IsPinned && !p.IsModerator
            && p.GroupUserUID != UserUID
            && p.Group.OwnerUID != p.GroupUserUID
            && p.GroupUser.LastLoggedIn.AddDays(days) < DateTime.UtcNow);

        if (!execute) return usersToPrune.Count();

        DbContext.GroupPairs.RemoveRange(usersToPrune);

        foreach (var pair in usersToPrune)
        {
            await Clients.Users(allGroupUsers.Where(p => !usersToPrune.Contains(p)).Select(g => g.GroupUserUID))
                .Client_GroupPairLeft(new GroupPairDto(dto.Group, pair.GroupUser.ToUserData())).ConfigureAwait(false);
        }

        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        return usersToPrune.Count();
    }

    [Authorize(Policy = "Identified")]
    public async Task GroupRemoveUser(GroupPairDto dto)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));

        var (hasRights, group) = await TryValidateGroupModeratorOrOwner(dto.Group.GID).ConfigureAwait(false);
        if (!hasRights) return;

        var (userExists, groupPair) = await TryValidateUserInGroup(dto.Group.GID, dto.User.UID).ConfigureAwait(false);
        if (!userExists) return;

        if (groupPair.IsModerator || string.Equals(group.OwnerUID, dto.User.UID, StringComparison.Ordinal)) return;
        _logger.LogCallInfo(MareHubLogger.Args(dto, "Success"));

        DbContext.GroupPairs.Remove(groupPair);
        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        var groupPairs = DbContext.GroupPairs.Where(p => p.GroupGID == group.GID).AsNoTracking().ToList();
        await Clients.Users(groupPairs.Select(p => p.GroupUserUID)).Client_GroupPairLeft(dto).ConfigureAwait(false);

        var sharedData = await DbContext.CharaDataAllowances.Where(u => u.AllowedGroup != null && u.AllowedGroupGID == dto.GID && u.ParentUploaderUID == dto.UID).ToListAsync().ConfigureAwait(false);
        DbContext.CharaDataAllowances.RemoveRange(sharedData);

        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        var userIdent = await GetUserIdent(dto.User.UID).ConfigureAwait(false);
        if (userIdent == null) return;

        await Clients.User(dto.User.UID).Client_GroupDelete(new GroupDto(dto.Group)).ConfigureAwait(false);

        var allUserPairs = await GetAllPairedClientsWithPauseState(dto.User.UID).ConfigureAwait(false);

        foreach (var groupUserPair in groupPairs)
        {
            await UserGroupLeave(groupUserPair, allUserPairs, userIdent, dto.User.UID).ConfigureAwait(false);
        }
    }

    [Authorize(Policy = "Identified")]
    public async Task GroupSetUserInfo(GroupPairUserInfoDto dto)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));

        var (userExists, userPair) = await TryValidateUserInGroup(dto.Group.GID, dto.User.UID).ConfigureAwait(false);
        if (!userExists) return;

        var (userIsOwner, _) = await TryValidateOwner(dto.Group.GID).ConfigureAwait(false);
        var (userIsModerator, _) = await TryValidateGroupModeratorOrOwner(dto.Group.GID).ConfigureAwait(false);

        if (dto.GroupUserInfo.HasFlag(GroupUserInfo.IsPinned) && userIsModerator && !userPair.IsPinned)
        {
            userPair.IsPinned = true;
        }
        else if (userIsModerator && userPair.IsPinned)
        {
            userPair.IsPinned = false;
        }

        if (dto.GroupUserInfo.HasFlag(GroupUserInfo.IsModerator) && userIsOwner && !userPair.IsModerator)
        {
            userPair.IsModerator = true;
        }
        else if (userIsOwner && userPair.IsModerator)
        {
            userPair.IsModerator = false;
        }

        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        var groupPairs = await DbContext.GroupPairs.AsNoTracking().Where(p => p.GroupGID == dto.Group.GID).Select(p => p.GroupUserUID).ToListAsync().ConfigureAwait(false);
        await Clients.Users(groupPairs).Client_GroupPairChangeUserInfo(new GroupPairUserInfoDto(dto.Group, dto.User, userPair.GetGroupPairUserInfo())).ConfigureAwait(false);
    }

    [Authorize(Policy = "Identified")]
    public async Task<List<GroupFullInfoDto>> GroupsGetAll()
    {
        _logger.LogCallInfo();

        var groups = await DbContext.GroupPairs.Include(g => g.Group).Include(g => g.Group.Owner).Where(g => g.GroupUserUID == UserUID).AsNoTracking().ToListAsync().ConfigureAwait(false);

        return groups.Select(g => new GroupFullInfoDto(g.Group.ToGroupData(), g.Group.Owner.ToUserData(),
                g.Group.GetGroupPermissions(), g.GetGroupPairPermissions(), g.GetGroupPairUserInfo())).ToList();
    }

    [Authorize(Policy = "Identified")]
    public async Task<List<GroupPairFullInfoDto>> GroupsGetUsersInGroup(GroupDto dto)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));

        var (inGroup, _) = await TryValidateUserInGroup(dto.Group.GID).ConfigureAwait(false);
        if (!inGroup) return new List<GroupPairFullInfoDto>();

        var group = await DbContext.Groups.SingleAsync(g => g.GID == dto.Group.GID).ConfigureAwait(false);
        var allPairs = await DbContext.GroupPairs.Include(g => g.GroupUser).Where(g => g.GroupGID == dto.Group.GID && g.GroupUserUID != UserUID).AsNoTracking().ToListAsync().ConfigureAwait(false);
        return allPairs.Select(p => new GroupPairFullInfoDto(group.ToGroupData(), p.GroupUser.ToUserData(), p.GetGroupPairUserInfo(), p.GetGroupPairPermissions())).ToList();
    }

    [Authorize(Policy = "Identified")]
    public async Task GroupUnbanUser(GroupPairDto dto)
    {
        _logger.LogCallInfo(MareHubLogger.Args(dto));

        var (userHasRights, _) = await TryValidateGroupModeratorOrOwner(dto.Group.GID).ConfigureAwait(false);
        if (!userHasRights) return;

        var banEntry = await DbContext.GroupBans.SingleOrDefaultAsync(g => g.GroupGID == dto.Group.GID && g.BannedUserUID == dto.User.UID).ConfigureAwait(false);
        if (banEntry == null) return;

        DbContext.Remove(banEntry);
        await DbContext.SaveChangesAsync().ConfigureAwait(false);

        _logger.LogCallInfo(MareHubLogger.Args(dto, "Success"));
    }
}