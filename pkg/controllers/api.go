package controllers

import (
	"context"

	"github.com/zeiss/fiber-goth/pkg/apis"
)

var _ apis.StrictServerInterface = (*APIController)(nil)

type APIController struct{}

func NewAPIController() *APIController {
	return &APIController{}
}

// (GET /account-info).
func (c *APIController) GetAccountInfo(_ context.Context, _ apis.GetAccountInfoRequestObject) (apis.GetAccountInfoResponseObject, error) {
	return apis.GetAccountInfo200JSONResponse{}, nil
}

// (POST /change-email).
func (c *APIController) ChangeEmail(_ context.Context, _ apis.ChangeEmailRequestObject) (apis.ChangeEmailResponseObject, error) {
	return apis.ChangeEmail200JSONResponse{}, nil
}

// (POST /change-password).
func (c *APIController) ChangePassword(_ context.Context, _ apis.ChangePasswordRequestObject) (apis.ChangePasswordResponseObject, error) {
	return apis.ChangePassword200JSONResponse{}, nil
}

// (POST /delete-user).
func (c *APIController) DeleteUser(_ context.Context, _ apis.DeleteUserRequestObject) (apis.DeleteUserResponseObject, error) {
	return apis.DeleteUser200JSONResponse{}, nil
}

// (GET /delete-user/callback).
func (c *APIController) GetDeleteUserCallback(_ context.Context, _ apis.GetDeleteUserCallbackRequestObject) (apis.GetDeleteUserCallbackResponseObject, error) {
	return apis.GetDeleteUserCallback200JSONResponse{}, nil
}

// (GET /error).
func (c *APIController) GetError(_ context.Context, _ apis.GetErrorRequestObject) (apis.GetErrorResponseObject, error) {
	return apis.GetError200TexthtmlResponse{}, nil
}

// (POST /get-access-token).
func (c *APIController) PostGetAccessToken(_ context.Context, _ apis.PostGetAccessTokenRequestObject) (apis.PostGetAccessTokenResponseObject, error) {
	return apis.PostGetAccessToken200JSONResponse{}, nil
}

// (GET /get-session).
func (c *APIController) GetSession(_ context.Context, _ apis.GetSessionRequestObject) (apis.GetSessionResponseObject, error) {
	return apis.GetSession200JSONResponse{}, nil
}

// (POST /link-social).
func (c *APIController) LinkSocialAccount(_ context.Context, _ apis.LinkSocialAccountRequestObject) (apis.LinkSocialAccountResponseObject, error) {
	return apis.LinkSocialAccount200JSONResponse{}, nil
}

// (GET /list-accounts).
func (c *APIController) ListUserAccounts(_ context.Context, _ apis.ListUserAccountsRequestObject) (apis.ListUserAccountsResponseObject, error) {
	return apis.ListUserAccounts200JSONResponse{}, nil
}

// (GET /list-sessions).
func (c *APIController) ListUserSessions(_ context.Context, _ apis.ListUserSessionsRequestObject) (apis.ListUserSessionsResponseObject, error) {
	return apis.ListUserSessions200JSONResponse{}, nil
}

// (GET /ok).
func (c *APIController) GetOk(_ context.Context, _ apis.GetOkRequestObject) (apis.GetOkResponseObject, error) {
	return apis.GetOk200JSONResponse{}, nil
}

// (POST /organization/accept-invitation).
func (c *APIController) PostOrganizationAcceptInvitation(_ context.Context, _ apis.PostOrganizationAcceptInvitationRequestObject) (apis.PostOrganizationAcceptInvitationResponseObject, error) {
	return apis.PostOrganizationAcceptInvitation200JSONResponse{}, nil
}

// (POST /organization/add-team-member).
func (c *APIController) PostOrganizationAddTeamMember(_ context.Context, _ apis.PostOrganizationAddTeamMemberRequestObject) (apis.PostOrganizationAddTeamMemberResponseObject, error) {
	return apis.PostOrganizationAddTeamMember200JSONResponse{}, nil
}

// (POST /organization/cancel-invitation).
func (c *APIController) PostOrganizationCancelInvitation(_ context.Context, _ apis.PostOrganizationCancelInvitationRequestObject) (apis.PostOrganizationCancelInvitationResponseObject, error) {
	return nil, nil
}

// (POST /organization/check-slug).
func (c *APIController) PostOrganizationCheckSlug(_ context.Context, _ apis.PostOrganizationCheckSlugRequestObject) (apis.PostOrganizationCheckSlugResponseObject, error) {
	return nil, nil
}

// (POST /organization/create).
func (c *APIController) PostOrganizationCreate(_ context.Context, _ apis.PostOrganizationCreateRequestObject) (apis.PostOrganizationCreateResponseObject, error) {
	return nil, nil
}

// (POST /organization/create-team).
func (c *APIController) PostOrganizationCreateTeam(_ context.Context, _ apis.PostOrganizationCreateTeamRequestObject) (apis.PostOrganizationCreateTeamResponseObject, error) {
	return nil, nil
}

// (POST /organization/delete).
func (c *APIController) PostOrganizationDelete(_ context.Context, _ apis.PostOrganizationDeleteRequestObject) (apis.PostOrganizationDeleteResponseObject, error) {
	return nil, nil
}

// (GET /organization/get-active-member).
func (c *APIController) GetOrganizationGetActiveMember(_ context.Context, _ apis.GetOrganizationGetActiveMemberRequestObject) (apis.GetOrganizationGetActiveMemberResponseObject, error) {
	return apis.GetOrganizationGetActiveMember200JSONResponse{}, nil
}

// (GET /organization/get-active-member-role).
func (c *APIController) GetOrganizationGetActiveMemberRole(_ context.Context, _ apis.GetOrganizationGetActiveMemberRoleRequestObject) (apis.GetOrganizationGetActiveMemberRoleResponseObject, error) {
	return nil, nil
}

// (GET /organization/get-full-organization).
func (c *APIController) GetOrganization(_ context.Context, _ apis.GetOrganizationRequestObject) (apis.GetOrganizationResponseObject, error) {
	return apis.GetOrganization200JSONResponse{}, nil
}

// (GET /organization/get-invitation).
func (c *APIController) GetOrganizationGetInvitation(_ context.Context, _ apis.GetOrganizationGetInvitationRequestObject) (apis.GetOrganizationGetInvitationResponseObject, error) {
	return apis.GetOrganizationGetInvitation200JSONResponse{}, nil
}

// (POST /organization/has-permission).
func (c *APIController) PostOrganizationHasPermission(_ context.Context, _ apis.PostOrganizationHasPermissionRequestObject) (apis.PostOrganizationHasPermissionResponseObject, error) {
	return nil, nil
}

// (POST /organization/invite-member).
func (c *APIController) CreateOrganizationInvitation(_ context.Context, _ apis.CreateOrganizationInvitationRequestObject) (apis.CreateOrganizationInvitationResponseObject, error) {
	return nil, nil
}

// (POST /organization/leave).
func (c *APIController) PostOrganizationLeave(_ context.Context, _ apis.PostOrganizationLeaveRequestObject) (apis.PostOrganizationLeaveResponseObject, error) {
	return nil, nil
}

// (GET /organization/list).
func (c *APIController) GetOrganizationList(_ context.Context, _ apis.GetOrganizationListRequestObject) (apis.GetOrganizationListResponseObject, error) {
	return apis.GetOrganizationList200JSONResponse{}, nil
}

// (GET /organization/list-invitations).
func (c *APIController) GetOrganizationListInvitations(_ context.Context, _ apis.GetOrganizationListInvitationsRequestObject) (apis.GetOrganizationListInvitationsResponseObject, error) {
	return nil, nil
}

// (GET /organization/list-members).
func (c *APIController) GetOrganizationListMembers(_ context.Context, _ apis.GetOrganizationListMembersRequestObject) (apis.GetOrganizationListMembersResponseObject, error) {
	return nil, nil
}

// (GET /organization/list-team-members).
func (c *APIController) GetOrganizationListTeamMembers(_ context.Context, _ apis.GetOrganizationListTeamMembersRequestObject) (apis.GetOrganizationListTeamMembersResponseObject, error) {
	return apis.GetOrganizationListTeamMembers200JSONResponse{}, nil
}

// (GET /organization/list-teams).
func (c *APIController) GetOrganizationListTeams(_ context.Context, _ apis.GetOrganizationListTeamsRequestObject) (apis.GetOrganizationListTeamsResponseObject, error) {
	return apis.GetOrganizationListTeams200JSONResponse{}, nil
}

// (GET /organization/list-user-invitations).
func (c *APIController) GetOrganizationListUserInvitations(_ context.Context, _ apis.GetOrganizationListUserInvitationsRequestObject) (apis.GetOrganizationListUserInvitationsResponseObject, error) {
	return apis.GetOrganizationListUserInvitations200JSONResponse{}, nil
}

// (GET /organization/list-user-teams).
func (c *APIController) GetOrganizationListUserTeams(_ context.Context, _ apis.GetOrganizationListUserTeamsRequestObject) (apis.GetOrganizationListUserTeamsResponseObject, error) {
	return apis.GetOrganizationListUserTeams200JSONResponse{}, nil
}

// (POST /organization/reject-invitation).
func (c *APIController) PostOrganizationRejectInvitation(_ context.Context, _ apis.PostOrganizationRejectInvitationRequestObject) (apis.PostOrganizationRejectInvitationResponseObject, error) {
	return nil, nil
}

// (POST /organization/remove-member).
func (c *APIController) PostOrganizationRemoveMember(_ context.Context, _ apis.PostOrganizationRemoveMemberRequestObject) (apis.PostOrganizationRemoveMemberResponseObject, error) {
	return nil, nil
}

// (POST /organization/remove-team).
func (c *APIController) PostOrganizationRemoveTeam(_ context.Context, _ apis.PostOrganizationRemoveTeamRequestObject) (apis.PostOrganizationRemoveTeamResponseObject, error) {
	return nil, nil
}

// (POST /organization/remove-team-member).
func (c *APIController) PostOrganizationRemoveTeamMember(_ context.Context, _ apis.PostOrganizationRemoveTeamMemberRequestObject) (apis.PostOrganizationRemoveTeamMemberResponseObject, error) {
	return nil, nil
}

// (POST /organization/set-active).
func (c *APIController) SetActiveOrganization(_ context.Context, _ apis.SetActiveOrganizationRequestObject) (apis.SetActiveOrganizationResponseObject, error) {
	return nil, nil
}

// (POST /organization/set-active-team).
func (c *APIController) PostOrganizationSetActiveTeam(_ context.Context, _ apis.PostOrganizationSetActiveTeamRequestObject) (apis.PostOrganizationSetActiveTeamResponseObject, error) {
	return apis.PostOrganizationSetActiveTeam200JSONResponse{}, nil
}

// (POST /organization/update).
func (c *APIController) PostOrganizationUpdate(_ context.Context, _ apis.PostOrganizationUpdateRequestObject) (apis.PostOrganizationUpdateResponseObject, error) {
	return nil, nil
}

// (POST /organization/update-member-role).
func (c *APIController) UpdateOrganizationMemberRole(_ context.Context, _ apis.UpdateOrganizationMemberRoleRequestObject) (apis.UpdateOrganizationMemberRoleResponseObject, error) {
	return apis.UpdateOrganizationMemberRole200JSONResponse{}, nil
}

// (POST /organization/update-team).
func (c *APIController) PostOrganizationUpdateTeam(_ context.Context, _ apis.PostOrganizationUpdateTeamRequestObject) (apis.PostOrganizationUpdateTeamResponseObject, error) {
	return nil, nil
}

// (POST /refresh-token).
func (c *APIController) PostRefreshToken(_ context.Context, _ apis.PostRefreshTokenRequestObject) (apis.PostRefreshTokenResponseObject, error) {
	return nil, nil
}

// (POST /request-password-reset).
func (c *APIController) RequestPasswordReset(_ context.Context, _ apis.RequestPasswordResetRequestObject) (apis.RequestPasswordResetResponseObject, error) {
	return apis.RequestPasswordReset200JSONResponse{}, nil
}

// (POST /reset-password).
func (c *APIController) ResetPassword(_ context.Context, _ apis.ResetPasswordRequestObject) (apis.ResetPasswordResponseObject, error) {
	return nil, nil
}

// (GET /reset-password/{token}).
func (c *APIController) ResetPasswordCallback(_ context.Context, _ apis.ResetPasswordCallbackRequestObject) (apis.ResetPasswordCallbackResponseObject, error) {
	return apis.ResetPasswordCallback200JSONResponse{}, nil
}

// (POST /revoke-other-sessions).
func (c *APIController) PostRevokeOtherSessions(_ context.Context, _ apis.PostRevokeOtherSessionsRequestObject) (apis.PostRevokeOtherSessionsResponseObject, error) {
	return apis.PostRevokeOtherSessions200JSONResponse{}, nil
}

// (POST /revoke-session).
func (c *APIController) PostRevokeSession(_ context.Context, _ apis.PostRevokeSessionRequestObject) (apis.PostRevokeSessionResponseObject, error) {
	return nil, nil
}

// (POST /revoke-sessions).
func (c *APIController) PostRevokeSessions(_ context.Context, _ apis.PostRevokeSessionsRequestObject) (apis.PostRevokeSessionsResponseObject, error) {
	return nil, nil
}

// (POST /send-verification-email).
func (c *APIController) SendVerificationEmail(_ context.Context, _ apis.SendVerificationEmailRequestObject) (apis.SendVerificationEmailResponseObject, error) {
	return apis.SendVerificationEmail200JSONResponse{}, nil
}

// (POST /sign-in/email).
func (c *APIController) SignInEmail(_ context.Context, _ apis.SignInEmailRequestObject) (apis.SignInEmailResponseObject, error) {
	return apis.SignInEmail200JSONResponse{}, nil
}

// (POST /sign-in/social).
func (c *APIController) SocialSignIn(_ context.Context, _ apis.SocialSignInRequestObject) (apis.SocialSignInResponseObject, error) {
	return apis.SocialSignIn200JSONResponse{}, nil
}

// (POST /sign-out).
func (c *APIController) SignOut(_ context.Context, _ apis.SignOutRequestObject) (apis.SignOutResponseObject, error) {
	return apis.SignOut200JSONResponse{}, nil
}

// (POST /sign-up/email).
func (c *APIController) SignUpWithEmailAndPassword(_ context.Context, _ apis.SignUpWithEmailAndPasswordRequestObject) (apis.SignUpWithEmailAndPasswordResponseObject, error) {
	return apis.SignUpWithEmailAndPassword200JSONResponse{}, nil
}

// (POST /unlink-account).
func (c *APIController) PostUnlinkAccount(_ context.Context, _ apis.PostUnlinkAccountRequestObject) (apis.PostUnlinkAccountResponseObject, error) {
	return nil, nil
}

// (POST /update-user).
func (c *APIController) UpdateUser(_ context.Context, _ apis.UpdateUserRequestObject) (apis.UpdateUserResponseObject, error) {
	return apis.UpdateUser200JSONResponse{}, nil
}

// (GET /verify-email).
func (c *APIController) GetVerifyEmail(_ context.Context, _ apis.GetVerifyEmailRequestObject) (apis.GetVerifyEmailResponseObject, error) {
	return apis.GetVerifyEmail200JSONResponse{}, nil
}
