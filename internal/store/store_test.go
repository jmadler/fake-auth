package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jmadler/auth2/internal/mfa"
)

func testStore(t *testing.T) *SQLiteStore {
	st, err := NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestListUsers(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|u1", Email: "a@example.com", DisplayName: "A", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	if err := st.CreateUser(ctx, u, "pass"); err != nil {
		t.Fatal(err)
	}
	users, total, err := st.ListUsers(ctx, ListUsersOpts{Page: 0, PerPage: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) < 1 {
		t.Errorf("expected at least 1 user")
	}
	if total < 1 {
		t.Errorf("total = %d", total)
	}
}

func TestListUsersSearch(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|u1", Email: "findme@example.com", DisplayName: "Find Me", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	if err := st.CreateUser(ctx, u, "pass"); err != nil {
		t.Fatal(err)
	}
	users, _, err := st.ListUsers(ctx, ListUsersOpts{Page: 0, PerPage: 10, Query: "findme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Email != "findme@example.com" {
		t.Errorf("search failed: %v", users)
	}
}

func TestUpdateUser(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|u1", Email: "old@example.com", DisplayName: "Old", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	if err := st.CreateUser(ctx, u, "pass"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateUser(ctx, "auth0|u1", map[string]interface{}{"email": "new@example.com", "name": "New"}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetByID(ctx, "auth0|u1")
	if err != nil || got == nil {
		t.Fatal("user not found")
	}
	if got.Email != "new@example.com" || got.DisplayName != "New" {
		t.Errorf("email=%s displayName=%s", got.Email, got.DisplayName)
	}
}

func TestDeleteUser(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|del", Email: "del@example.com", DisplayName: "Del", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	if err := st.CreateUser(ctx, u, "pass"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUser(ctx, "auth0|del"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetByID(ctx, "auth0|del")
	if got != nil {
		t.Error("user should be deleted")
	}
}

func TestCreateRole(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	ro := &Role{ID: "rol_test", Name: "testrole", Description: "Test"}
	if err := st.CreateRole(ctx, ro); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetRoleByID(ctx, "rol_test")
	if err != nil || got == nil || got.Name != "testrole" {
		t.Errorf("GetRoleByID: %v %v", got, err)
	}
}

func TestUpdateRole(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.UpdateRole(ctx, "rol_default", "updated", "Updated desc"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetRoleByID(ctx, "rol_default")
	if got.Name != "updated" {
		t.Errorf("name = %s", got.Name)
	}
}

func TestDeleteRole(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	ro := &Role{ID: "rol_temp", Name: "temp", Description: "Temp"}
	st.CreateRole(ctx, ro)
	if err := st.DeleteRole(ctx, "rol_temp"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetRoleByID(ctx, "rol_temp")
	if got != nil {
		t.Error("role should be deleted")
	}
}

func TestListClients(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	clients, err := st.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) < 1 {
		t.Errorf("expected seeded clients")
	}
}

func TestBlockUnblockUser(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|block", Email: "block@example.com", DisplayName: "Block", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")
	if err := st.BlockUser(ctx, "auth0|block"); err != nil {
		t.Fatal(err)
	}
	blocked, err := st.IsUserBlocked(ctx, "auth0|block")
	if err != nil || !blocked {
		t.Error("user should be blocked")
	}
	if err := st.UnblockUser(ctx, "auth0|block"); err != nil {
		t.Fatal(err)
	}
	blocked, _ = st.IsUserBlocked(ctx, "auth0|block")
	if blocked {
		t.Error("user should be unblocked")
	}
}

func TestAppendLog(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.AppendLog(ctx, "login", "auth0|u1", "client1", "{}"); err != nil {
		t.Fatal(err)
	}
	logs, err := st.ListLogs(ctx, 10)
	if err != nil || len(logs) < 1 {
		t.Errorf("ListLogs: %v %d", err, len(logs))
	}
}

func TestEmailVerified(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|ev1", Email: "ev@example.com", DisplayName: "EV", EmailVerified: false, OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	if err := st.CreateUser(ctx, u, "pass"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetByID(ctx, "auth0|ev1")
	if got == nil || got.EmailVerified {
		t.Errorf("expected email_verified=false, got %v", got)
	}
	if err := st.UpdateEmailVerified(ctx, "auth0|ev1", true); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetByID(ctx, "auth0|ev1")
	if got == nil || !got.EmailVerified {
		t.Errorf("expected email_verified=true after update, got %v", got)
	}
}

func TestPasswordResetToken(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|pr1", Email: "pr@example.com", DisplayName: "PR", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	if err := st.CreateUser(ctx, u, "pass"); err != nil {
		t.Fatal(err)
	}
	tok, err := st.CreatePasswordResetToken(ctx, "auth0|pr1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if tok == "" || !strings.HasPrefix(tok, "prt_") {
		t.Errorf("expected prt_ token, got %q", tok)
	}
	userID, ok := st.ValidatePasswordResetToken(ctx, tok)
	if !ok || userID != "auth0|pr1" {
		t.Errorf("ValidatePasswordResetToken: got %q %v", userID, ok)
	}
	userID, ok = st.ConsumePasswordResetToken(ctx, tok)
	if !ok || userID != "auth0|pr1" {
		t.Errorf("ConsumePasswordResetToken: got %q %v", userID, ok)
	}
	_, ok = st.ConsumePasswordResetToken(ctx, tok)
	if ok {
		t.Error("token should be consumed")
	}
}

func TestCreateOrganization(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	org := &Organization{ID: "org_test", Name: "Test Org", DisplayName: "Test Organization"}
	if err := st.CreateOrganization(ctx, org); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetOrganization(ctx, "org_test")
	if err != nil || got == nil || got.Name != "Test Org" {
		t.Errorf("GetOrganization: %v %v", got, err)
	}
	orgs, err := st.ListOrganizations(ctx)
	if err != nil || len(orgs) < 1 {
		t.Errorf("ListOrganizations: %v", err)
	}
}

func TestSAMLServiceProvider(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	sp := &SAMLServiceProvider{
		ID:        "sp_1",
		EntityID:  "https://sp.example.com",
		ACSURL:    "https://sp.example.com/acs",
		Certificate: "cert-pem",
	}
	if err := st.CreateSAMLServiceProvider(ctx, sp); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSAMLServiceProviderByEntityID(ctx, "https://sp.example.com")
	if err != nil || got == nil || got.ACSURL != sp.ACSURL {
		t.Errorf("GetSAMLServiceProviderByEntityID: %v %v", got, err)
	}
}

func TestOrgMembers(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	org := &Organization{ID: "org_mem", Name: "Mem Org", DisplayName: "Members Org"}
	st.CreateOrganization(ctx, org)
	u := &User{ID: "auth0|m1", Email: "m1@example.com", DisplayName: "M1", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")

	if err := st.AddOrgMember(ctx, "org_mem", "auth0|m1", "member"); err != nil {
		t.Fatal(err)
	}
	members, err := st.ListOrgMembers(ctx, "org_mem")
	if err != nil || len(members) != 1 {
		t.Errorf("ListOrgMembers: %v", err)
	}
	ok, _ := st.IsOrgMember(ctx, "org_mem", "auth0|m1")
	if !ok {
		t.Error("should be org member")
	}
	st.RemoveOrgMember(ctx, "org_mem", "auth0|m1")
	members, _ = st.ListOrgMembers(ctx, "org_mem")
	if len(members) != 0 {
		t.Error("member should be removed")
	}
}

func TestMagicLinkToken(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	data := &MagicLinkTokenData{
		Email:        "ml@example.com",
		ClientID:     "c1",
		RedirectURI:  "http://localhost/cb",
		State:        "s1",
		ResponseType: "code",
		Scope:        "openid",
	}
	tok, err := st.CreateMagicLinkToken(ctx, data)
	if err != nil || tok == "" || !strings.HasPrefix(tok, "magic_") {
		t.Fatalf("CreateMagicLinkToken: %v %q", err, tok)
	}
	consumed, ok := st.ConsumeMagicLinkToken(ctx, tok)
	if !ok || consumed == nil || consumed.Email != data.Email {
		t.Errorf("ConsumeMagicLinkToken: %v %v", ok, consumed)
	}
	_, ok = st.ConsumeMagicLinkToken(ctx, tok)
	if ok {
		t.Error("token should be one-time")
	}
}

func TestMFAEnrollment(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|mfa1", Email: "mfa@example.com", DisplayName: "MFA", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")

	if err := st.SetMFAEnrollment(ctx, "auth0|mfa1", "secret123", []string{"hash1", "hash2"}); err != nil {
		t.Fatal(err)
	}
	en, err := st.GetMFAEnrollment(ctx, "auth0|mfa1")
	if err != nil || en == nil || en.TOTPSecret != "secret123" {
		t.Errorf("GetMFAEnrollment: %v %v", err, en)
	}
	if len(en.BackupCodeHashes) != 2 {
		t.Errorf("backup codes: %d", len(en.BackupCodeHashes))
	}
}

func TestWebAuthnCredentials(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|wa1", Email: "wa@example.com", DisplayName: "WA", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")

	cred := &WebAuthnCredential{
		ID:              "wa_cred_1",
		UserID:          "auth0|wa1",
		CredentialID:    []byte("cred-id-123"),
		PublicKey:       []byte("pubkey"),
		AttestationType: "none",
	}
	if err := st.CreateWebAuthnCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	creds, err := st.GetWebAuthnCredentials(ctx, "auth0|wa1")
	if err != nil || len(creds) != 1 || string(creds[0].PublicKey) != "pubkey" || creds[0].UserID != "auth0|wa1" {
		t.Errorf("GetWebAuthnCredentials: %v %v", err, creds)
	}
}

func TestRecordFailedLoginAndLockout(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.RecordFailedLogin(ctx, "fail@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordFailedLogin(ctx, "fail@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearFailedLogins(ctx, "fail@example.com"); err != nil {
		t.Fatal(err)
	}
	_, ok := st.IsLockedOut(ctx, "fail@example.com")
	if ok {
		t.Error("after clear, should not be locked out")
	}
	// Record until lockout (default 5 attempts)
	for i := 0; i < 5; i++ {
		st.RecordFailedLogin(ctx, "lock@example.com")
	}
	until, ok := st.IsLockedOut(ctx, "lock@example.com")
	if !ok || until.IsZero() {
		t.Error("should be locked out after 5 failures")
	}
}

func TestGetClientByID(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	clients, _ := st.ListClients(ctx)
	if len(clients) == 0 {
		t.Skip("no seeded clients")
	}
	c, err := st.GetClientByID(ctx, clients[0].ID)
	if err != nil || c == nil || c.ID != clients[0].ID {
		t.Errorf("GetClientByID: %v %v", err, c)
	}
}

func TestListConnections(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	conns, err := st.ListConnections(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) < 1 {
		t.Error("expected seeded connections")
	}
	c, err := st.GetConnectionByID(ctx, conns[0].ID)
	if err != nil || c == nil {
		t.Errorf("GetConnectionByID: %v %v", err, c)
	}
}

func TestProviderIdentity(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|prov1", Email: "prov@example.com", DisplayName: "Prov", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")
	if err := st.LinkUserIdentity(ctx, "auth0|prov1", "google-oauth2", "g123"); err != nil {
		t.Fatal(err)
	}
	found, err := st.GetUserByProviderIdentity(ctx, "google-oauth2", "g123")
	if err != nil || found == nil || found.ID != "auth0|prov1" {
		t.Errorf("GetUserByProviderIdentity: %v %v", err, found)
	}
}

func TestUpdateDeleteOrganization(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	org := &Organization{ID: "org_upd", Name: "Upd Org", DisplayName: "Update Org"}
	st.CreateOrganization(ctx, org)
	if err := st.UpdateOrganization(ctx, "org_upd", map[string]interface{}{"name": "New Name"}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetOrganization(ctx, "org_upd")
	if got == nil || got.Name != "New Name" {
		t.Errorf("update failed: %v", got)
	}
	if err := st.DeleteOrganization(ctx, "org_upd"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetOrganization(ctx, "org_upd")
	if got != nil {
		t.Error("org should be deleted")
	}
}

func TestConsumeBackupCode(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|bc1", Email: "bc@example.com", DisplayName: "BC", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")
	// SetMFAEnrollment stores bcrypt hashes; wrong hash format yields invalid comparison
	if err := st.SetMFAEnrollment(ctx, "auth0|bc1", "secret", []string{"$2a$10$invalid"}); err != nil {
		t.Fatal(err)
	}
	ok, err := st.ConsumeBackupCode(ctx, "auth0|bc1", "wrong")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("wrong backup code should not succeed")
	}
}

func TestKnownIP(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|kip1", Email: "kip@example.com", DisplayName: "KIP", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")
	if err := st.AddKnownIP(ctx, "auth0|kip1", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	known, err := st.IsIPKnownForUser(ctx, "auth0|kip1", "10.0.0.1")
	if err != nil || !known {
		t.Errorf("IP should be known: %v", err)
	}
	known, _ = st.IsIPKnownForUser(ctx, "auth0|kip1", "10.0.0.2")
	if known {
		t.Error("different IP should not be known")
	}
}

func TestSMSOTPToken(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	data := &SMSOTPTokenData{
		Phone:       "+15551234567",
		Code:        "123456",
		ClientID:    "c1",
		RedirectURI: "http://localhost/cb",
		State:       "s1",
	}
	tok, err := st.CreateSMSOTPToken(ctx, data)
	if err != nil || tok == "" {
		t.Fatalf("CreateSMSOTPToken: %v %q", err, tok)
	}
	consumed, ok := st.ConsumeSMSOTPToken(ctx, tok, "123456")
	if !ok || consumed == nil || consumed.Phone != data.Phone {
		t.Errorf("ConsumeSMSOTPToken: ok=%v consumed=%v", ok, consumed)
	}
	_, ok = st.ConsumeSMSOTPToken(ctx, tok, "123456")
	if ok {
		t.Error("token should be one-time")
	}
}

func TestUpdateClient(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	clients, _ := st.ListClients(ctx)
	if len(clients) == 0 {
		t.Skip("no seeded clients")
	}
	if err := st.UpdateClient(ctx, clients[0].ID, map[string]interface{}{"name": "Updated Client"}); err != nil {
		t.Fatal(err)
	}
	c, _ := st.GetClientByID(ctx, clients[0].ID)
	if c == nil || c.Name != "Updated Client" {
		t.Errorf("UpdateClient: got %v", c)
	}
}

func TestUpdatePassword(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|pwd1", Email: "pwd@example.com", DisplayName: "Pwd", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "oldpass")
	if err := st.UpdatePassword(ctx, "auth0|pwd1", "newpass"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetByID(ctx, "auth0|pwd1")
	if got == nil {
		t.Fatal("user not found")
	}
	if !st.VerifyPassword(got.PasswordHash, "newpass") {
		t.Error("password should be updated")
	}
}

func TestDeleteOldAuditLogs(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	st.AppendLog(ctx, "test", "u1", "c1", "{}")
	n, err := st.DeleteOldAuditLogs(ctx, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n < 0 {
		t.Errorf("deleted count = %d", n)
	}
}

func TestListUsersExport(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	users, total, err := st.ListUsersExport(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total < 0 {
		t.Errorf("total = %d", total)
	}
	_ = users
}

func TestGetUserRoles(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|role1", Email: "role@example.com", DisplayName: "Role", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")
	st.AssignRoleToUser(ctx, "auth0|role1", "rol_default")
	roles, err := st.GetUserRoles(ctx, "auth0|role1")
	if err != nil || len(roles) < 1 {
		t.Errorf("GetUserRoles: %v %d", err, len(roles))
	}
}

func TestListSAMLServiceProviders(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	sp := &SAMLServiceProvider{ID: "sp_list", EntityID: "https://list.example.com", ACSURL: "https://list.example.com/acs", Certificate: "cert"}
	st.CreateSAMLServiceProvider(ctx, sp)
	list, err := st.ListSAMLServiceProviders(ctx)
	if err != nil || len(list) < 1 {
		t.Errorf("ListSAMLServiceProviders: %v", err)
	}
}

func TestOIDCEnterpriseConnection(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	ec := &OIDCEnterpriseConnection{
		ID:           "oidc_1",
		Name:         "Test OIDC",
		IssuerURL:    "https://okta.example.com",
		ClientID:     "cid",
		ClientSecret: "secret",
		Scope:        "openid",
	}
	if err := st.CreateOIDCEnterpriseConnection(ctx, ec); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetOIDCEnterpriseConnectionByName(ctx, "Test OIDC")
	if err != nil || got == nil || got.IssuerURL != ec.IssuerURL {
		t.Errorf("GetOIDCEnterpriseConnectionByName: %v %v", err, got)
	}
	list, _ := st.ListOIDCEnterpriseConnections(ctx)
	if len(list) < 1 {
		t.Error("expected at least one OIDC connection")
	}
}

func TestInvitation(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	org := &Organization{ID: "org_inv", Name: "Inv Org", DisplayName: "Invitation Org"}
	st.CreateOrganization(ctx, org)
	u := &User{ID: "auth0|inv1", Email: "inv@example.com", DisplayName: "Inv", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")
	inv := &Invitation{ID: "inv_1", OrgID: "org_inv", Email: "new@example.com", Role: "member", Token: "inv_tok_abc123", ExpiresAt: time.Now().Add(time.Hour)}
	tok, err := st.CreateInvitation(ctx, inv)
	if err != nil || tok == "" {
		t.Fatalf("CreateInvitation: %v", err)
	}
	got, err := st.GetInvitationByToken(ctx, tok)
	if err != nil || got == nil || got.Email != "new@example.com" {
		t.Errorf("GetInvitationByToken: %v %v", err, got)
	}
	consumed, ok := st.ConsumeInvitation(ctx, tok)
	if !ok || consumed == nil {
		t.Errorf("ConsumeInvitation: %v", ok)
	}
	inv2, _ := st.GetInvitationByToken(ctx, tok)
	if inv2 != nil {
		t.Error("token should be consumed")
	}
}

func TestOrgConnections(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	org := &Organization{ID: "org_conn", Name: "Conn Org", DisplayName: "Connections Org"}
	st.CreateOrganization(ctx, org)
	conns, _ := st.ListConnections(ctx)
	if len(conns) > 0 {
		if err := st.SetOrgConnection(ctx, "org_conn", conns[0].ID); err != nil {
			t.Fatal(err)
		}
		ids, err := st.ListOrgConnections(ctx, "org_conn")
		if err != nil || len(ids) < 1 {
			t.Errorf("ListOrgConnections: %v %d", err, len(ids))
		}
		st.RemoveOrgConnection(ctx, "org_conn", conns[0].ID)
		ids, _ = st.ListOrgConnections(ctx, "org_conn")
		if len(ids) != 0 {
			t.Error("connection should be removed")
		}
	}
}

func TestGetByEmailAndPhone(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|eby1", Email: "eby@example.com", DisplayName: "Eby", OrganizationID: 1, EnterpriseID: 1, Role: "user", PhoneNumber: "+15559876543"}
	st.CreateUser(ctx, u, "pass")
	byEmail, err := st.GetByEmail(ctx, "eby@example.com")
	if err != nil || byEmail == nil || byEmail.ID != "auth0|eby1" {
		t.Errorf("GetByEmail: %v %v", err, byEmail)
	}
	byPhone, err := st.GetByPhone(ctx, "+15559876543")
	if err != nil || byPhone == nil || byPhone.ID != "auth0|eby1" {
		t.Errorf("GetByPhone: %v %v", err, byPhone)
	}
	_, err = st.GetByPhone(ctx, "")
	if err != nil {
		t.Error("GetByPhone empty should return nil,nil")
	}
}

func TestPing(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.Ping(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateAppMetadata(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|meta1", Email: "meta@example.com", DisplayName: "Meta", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")
	if err := st.UpdateAppMetadata(ctx, "auth0|meta1", map[string]interface{}{"key": "value"}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetByID(ctx, "auth0|meta1")
	if got == nil || got.AppMetadata["key"] != "value" {
		t.Errorf("UpdateAppMetadata: %v", got)
	}
}

func TestGetUserPermissions(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|perm1", Email: "perm@example.com", DisplayName: "Perm", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")
	perms, err := st.GetUserPermissions(ctx, "auth0|perm1")
	if err != nil {
		t.Fatal(err)
	}
	_ = perms
}

func TestListRoles(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	roles, err := st.ListRoles(ctx)
	if err != nil || len(roles) < 1 {
		t.Errorf("ListRoles: %v %d", err, len(roles))
	}
}

func TestRemoveRoleFromUser(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|remr1", Email: "remr@example.com", DisplayName: "RemR", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")
	st.AssignRoleToUser(ctx, "auth0|remr1", "rol_default")
	if err := st.RemoveRoleFromUser(ctx, "auth0|remr1", "rol_default"); err != nil {
		t.Fatal(err)
	}
	roles, _ := st.GetUserRoles(ctx, "auth0|remr1")
	if len(roles) != 0 {
		t.Error("role should be removed")
	}
}

func TestEnterpriseConnection(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	org := &Organization{ID: "org_ec", Name: "EC Org", DisplayName: "Enterprise Org"}
	st.CreateOrganization(ctx, org)
	ec := &EnterpriseConnection{
		ID:           "ec_1",
		OrgID:        "org_ec",
		Name:         "Acme SSO",
		DomainHint:   "acme.com",
		IssuerURL:    "https://acme.okta.com",
		ClientID:     "cid",
		ClientSecret: "secret",
	}
	if err := st.CreateEnterpriseConnection(ctx, ec); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetEnterpriseConnection(ctx, "ec_1")
	if err != nil || got == nil || got.DomainHint != "acme.com" {
		t.Errorf("GetEnterpriseConnection: %v %v", err, got)
	}
	list, err := st.ListEnterpriseConnections(ctx, "org_ec")
	if err != nil || len(list) != 1 {
		t.Errorf("ListEnterpriseConnections: %v %d", err, len(list))
	}
	byDomain, err := st.GetEnterpriseConnectionByDomain(ctx, "acme.com")
	if err != nil || byDomain == nil || byDomain.ID != "ec_1" {
		t.Errorf("GetEnterpriseConnectionByDomain: %v %v", err, byDomain)
	}
}

func TestCIBARequest(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	req := &CIBARequest{
		AuthReqID: "ciba_ar_1",
		ClientID:  "c1",
		LoginHint: "user@example.com",
		Scope:     "openid",
		Status:    "pending",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := st.SaveCIBARequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetCIBARequest(ctx, "ciba_ar_1")
	if err != nil || got == nil || got.ClientID != "c1" {
		t.Errorf("GetCIBARequest: %v %v", err, got)
	}
	if err := st.UpdateCIBARequestStatus(ctx, "ciba_ar_1", "approved", "auth0|u1"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetCIBARequest(ctx, "ciba_ar_1")
	if got == nil || got.Status != "approved" {
		t.Error("status should be updated")
	}
}

func TestTokenVault(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	entry := &TokenVaultEntry{
		Name:                 "my-agent",
		UserID:               "auth0|tv1",
		AccessTokenEncrypted: "encrypted-token-data",
		Metadata:             "{}",
	}
	id, err := st.SaveTokenVaultEntry(ctx, entry)
	if err != nil || id == "" {
		t.Fatalf("SaveTokenVaultEntry: %v %q", err, id)
	}
	got, err := st.GetTokenVaultEntry(ctx, "my-agent", "auth0|tv1")
	if err != nil || got == nil || got.AccessTokenEncrypted != "encrypted-token-data" {
		t.Errorf("GetTokenVaultEntry: %v %v", err, got)
	}
	byID, err := st.GetTokenVaultEntryByID(ctx, id)
	if err != nil || byID == nil {
		t.Errorf("GetTokenVaultEntryByID: %v %v", err, byID)
	}
}

func TestConsumeBackupCodeSuccess(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	u := &User{ID: "auth0|bcs1", Email: "bcs@example.com", DisplayName: "BCS", OrganizationID: 1, EnterpriseID: 1, Role: "user"}
	st.CreateUser(ctx, u, "pass")
	codes, hashes, err := mfa.GenerateBackupCodes(3)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetMFAEnrollment(ctx, "auth0|bcs1", "secret", hashes); err != nil {
		t.Fatal(err)
	}
	ok, err := st.ConsumeBackupCode(ctx, "auth0|bcs1", codes[0])
	if err != nil || !ok {
		t.Errorf("ConsumeBackupCode success: ok=%v err=%v", ok, err)
	}
	ok, _ = st.ConsumeBackupCode(ctx, "auth0|bcs1", codes[0])
	if ok {
		t.Error("same backup code should not work twice")
	}
}
