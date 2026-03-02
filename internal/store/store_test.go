package store

import (
	"context"
	"testing"
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
