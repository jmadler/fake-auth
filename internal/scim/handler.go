package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmadler/auth2/internal/audit"
	"github.com/jmadler/auth2/internal/password"
	"github.com/jmadler/auth2/internal/store"
)

// Handler serves SCIM 2.0 API.
type Handler struct {
	Store     store.Store
	IssuerURL string
}

// NewHandler creates a SCIM handler.
func NewHandler(st store.Store, issuerURL string) *Handler {
	issuerURL = strings.TrimSuffix(issuerURL, "/")
	return &Handler{Store: st, IssuerURL: issuerURL}
}

// ServeHTTP routes SCIM v2 requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	path = strings.TrimPrefix(path, "/scim/v2")
	if path == "" {
		path = "/"
	}

	switch {
	case r.Method == http.MethodGet && path == "/Users":
		h.listUsers(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/Users/"):
		h.getUser(w, r, strings.TrimPrefix(path, "/Users/"))
	case r.Method == http.MethodPost && path == "/Users":
		h.createUser(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/Users/"):
		h.patchUser(w, r, strings.TrimPrefix(path, "/Users/"))
	case r.Method == http.MethodPut && strings.HasPrefix(path, "/Users/"):
		h.putUser(w, r, strings.TrimPrefix(path, "/Users/"))
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/Users/"):
		h.deleteUser(w, r, strings.TrimPrefix(path, "/Users/"))
	case r.Method == http.MethodGet && path == "/Groups":
		h.listGroups(w, r)
	case r.Method == http.MethodGet && path == "/ResourceTypes":
		h.resourceTypes(w, r)
	case r.Method == http.MethodGet && path == "/Schemas":
		h.schemas(w, r)
	default:
		h.writeError(w, http.StatusNotFound, "invalidRequest", "Resource not found")
	}
}

func (h *Handler) setSCIMHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", ContentType)
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	h.setSCIMHeaders(w)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, scimType, detail string) {
	h.setSCIMHeaders(w)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"schemas":   []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"scimType":  scimType,
		"detail":    detail,
		"status":    strconv.Itoa(status),
	})
}

func (h *Handler) userLocation(id string) string {
	return h.IssuerURL + "/scim/v2/Users/" + id
}

// scimUserFromStore maps store.User to SCIM User.
func (h *Handler) scimUserFromStore(ctx context.Context, u *store.User) *User {
	primary := true
	emails := []EmailValue{{Value: u.Email, Type: "work", Primary: &primary}}
	name := &Name{}
	parts := strings.SplitN(u.DisplayName, " ", 2)
	if len(parts) >= 1 {
		name.GivenName = parts[0]
	}
	if len(parts) >= 2 {
		name.FamilyName = parts[1]
	}
	if name.GivenName == "" && name.FamilyName == "" {
		name.Formatted = u.DisplayName
	} else {
		name.Formatted = strings.TrimSpace(name.GivenName + " " + name.FamilyName)
	}
	if name.Formatted == "" {
		name.Formatted = u.Email
	}
	blocked, _ := h.Store.IsUserBlocked(ctx, u.ID)
	active := !blocked
	return &User{
		Schemas:     []string{UserSchema},
		ID:          u.ID,
		UserName:    u.Email,
		Name:        name,
		DisplayName: u.DisplayName,
		Emails:      emails,
		Active:      &active,
		Meta: &Meta{
			ResourceType: "User",
			Location:     h.userLocation(u.ID),
		},
	}
}

// storeUserFromSCIM maps SCIM User to store.User for create.
func storeUserFromSCIM(scim *User, id string) (*store.User, string) {
	email := scim.UserName
	if email == "" && len(scim.Emails) > 0 {
		for _, e := range scim.Emails {
			if e.Primary != nil && *e.Primary {
				email = e.Value
				break
			}
		}
		if email == "" {
			email = scim.Emails[0].Value
		}
	}
	displayName := scim.DisplayName
	if displayName == "" && scim.Name != nil {
		displayName = strings.TrimSpace(scim.Name.GivenName + " " + scim.Name.FamilyName)
		if displayName == "" {
			displayName = scim.Name.Formatted
		}
	}
	if displayName == "" {
		displayName = email
	}
	return &store.User{
		ID:             id,
		Email:          email,
		DisplayName:    displayName,
		EmailVerified:  true,
		OrganizationID: 1,
		EnterpriseID:   1,
		Role:           "user",
	}, email
}

// parseFilter extracts query from SCIM filter for userName/emails.
// Supports: userName eq "x", userName co "x", emails.value eq "x"
func parseFilter(filter string) string {
	if filter == "" {
		return ""
	}
	// userName eq "value" or userName EQ "value"
	re := regexp.MustCompile(`(?i)userName\s+(?:eq|co)\s+"([^"]*)"`)
	if m := re.FindStringSubmatch(filter); len(m) >= 2 {
		return m[1]
	}
	// emails[value eq "x" or primary eq true].value - simplified
	re2 := regexp.MustCompile(`(?i)emails.*?value\s+eq\s+"([^"]*)"`)
	if m := re2.FindStringSubmatch(filter); len(m) >= 2 {
		return m[1]
	}
	return ""
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	startIndex, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))

	if count <= 0 {
		count = 100
	}
	if count > 100 {
		count = 100
	}
	if startIndex <= 0 {
		startIndex = 1
	}

	query := parseFilter(filter)
	page := (startIndex - 1) / count
	perPage := count

	users, total, err := h.Store.ListUsers(r.Context(), store.ListUsersOpts{
		Page:    page,
		PerPage: perPage,
		Query:   query,
	})
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internalError", err.Error())
		return
	}

	resources := make([]interface{}, 0, len(users))
	for i := range users {
		u, err := h.Store.GetByID(r.Context(), users[i].ID)
		if err != nil || u == nil {
			continue
		}
		resources = append(resources, h.scimUserFromStore(r.Context(), u))
	}

	resp := ListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: total,
		ItemsPerPage: len(resources),
		StartIndex:   startIndex,
		Resources:    resources,
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "invalidValue", "User id required")
		return
	}
	u, err := h.Store.GetByID(r.Context(), id)
	if err != nil || u == nil {
		h.writeError(w, http.StatusNotFound, "invalidValue", "User not found")
		return
	}
	h.writeJSON(w, http.StatusOK, h.scimUserFromStore(r.Context(), u))
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	var scimUser User
	if err := json.NewDecoder(r.Body).Decode(&scimUser); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalidSyntax", "Invalid JSON body")
		return
	}
	scimUser.Schemas = []string{UserSchema}

	storeUser, email := storeUserFromSCIM(&scimUser, "")
	if email == "" {
		h.writeError(w, http.StatusBadRequest, "invalidValue", "userName or emails.value required")
		return
	}

	// Check existing by email
	existing, _ := h.Store.GetByEmail(r.Context(), email)
	if existing != nil {
		h.writeError(w, http.StatusConflict, "uniqueness", "User already exists with this userName/email")
		return
	}

	pwd := "ChangeMe123!"
	storeUser.ID = "auth0|" + uuid.New().String()

	if err := password.Validate(pwd); err != nil {
		pwd = "ChangeMe123!"
	}
	if err := h.Store.CreateUser(r.Context(), storeUser, pwd); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "duplicate") {
			h.writeError(w, http.StatusConflict, "uniqueness", "User already exists")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "internalError", err.Error())
		return
	}

	audit.LogUserChange("scim_create", storeUser.ID, true, nil)
	out := h.scimUserFromStore(r.Context(), storeUser)
	w.Header().Set("Location", h.userLocation(storeUser.ID))
	h.writeJSON(w, http.StatusCreated, out)
}

func (h *Handler) patchUser(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "invalidValue", "User id required")
		return
	}
	u, err := h.Store.GetByID(r.Context(), id)
	if err != nil || u == nil {
		h.writeError(w, http.StatusNotFound, "invalidValue", "User not found")
		return
	}

	var patch PatchRequest
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalidSyntax", "Invalid PATCH body")
		return
	}

	updates := make(map[string]interface{})
	for _, op := range patch.Operations {
		if op.Op != "replace" && op.Op != "add" {
			continue
		}
		path := strings.TrimPrefix(op.Path, "urn:ietf:params:scim:schemas:core:2.0:User:")
		if path == op.Path {
			path = op.Path
		}
		switch {
		case path == "userName", path == "emails":
			if m, ok := op.Value.(map[string]interface{}); ok {
				if v, ok := m["value"].(string); ok {
					updates["email"] = v
				}
			} else if arr, ok := op.Value.([]interface{}); ok {
				for _, it := range arr {
					if m, ok := it.(map[string]interface{}); ok {
						if v, ok := m["value"].(string); ok {
							primary, _ := m["primary"].(bool)
							if primary || len(updates) == 0 {
								updates["email"] = v
							}
						}
					}
				}
			} else if s, ok := op.Value.(string); ok {
				updates["email"] = s
			}
		case path == "name":
			if m, ok := op.Value.(map[string]interface{}); ok {
				given, _ := m["givenName"].(string)
				family, _ := m["familyName"].(string)
				formatted, _ := m["formatted"].(string)
				display := strings.TrimSpace(given + " " + family)
				if display == "" {
					display = formatted
				}
				if display != "" {
					updates["name"] = display
				}
			}
		case path == "displayName":
			if s, ok := op.Value.(string); ok {
				updates["name"] = s
			}
		case path == "active":
			if b, ok := op.Value.(bool); ok && !b {
				_ = h.Store.BlockUser(r.Context(), id)
			} else if b {
				_ = h.Store.UnblockUser(r.Context(), id)
			}
		}
	}

	if len(updates) > 0 {
		if err := h.Store.UpdateUser(r.Context(), id, updates); err != nil {
			h.writeError(w, http.StatusInternalServerError, "internalError", err.Error())
			return
		}
	}
	audit.LogUserChange("scim_patch", id, true, nil)
	updated, _ := h.Store.GetByID(r.Context(), id)
	h.writeJSON(w, http.StatusOK, h.scimUserFromStore(r.Context(), updated))
}

func (h *Handler) putUser(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "invalidValue", "User id required")
		return
	}
	u, err := h.Store.GetByID(r.Context(), id)
	if err != nil || u == nil {
		h.writeError(w, http.StatusNotFound, "invalidValue", "User not found")
		return
	}

	var scimUser User
	if err := json.NewDecoder(r.Body).Decode(&scimUser); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalidSyntax", "Invalid JSON body")
		return
	}

	updates := make(map[string]interface{})
	storeUser, email := storeUserFromSCIM(&scimUser, id)
	if email != "" {
		updates["email"] = email
	}
	if storeUser.DisplayName != "" {
		updates["name"] = storeUser.DisplayName
	}
	if scimUser.Active != nil && !*scimUser.Active {
		_ = h.Store.BlockUser(r.Context(), id)
	} else if scimUser.Active != nil && *scimUser.Active {
		_ = h.Store.UnblockUser(r.Context(), id)
	}

	if len(updates) > 0 {
		if err := h.Store.UpdateUser(r.Context(), id, updates); err != nil {
			h.writeError(w, http.StatusInternalServerError, "internalError", err.Error())
			return
		}
	}
	audit.LogUserChange("scim_put", id, true, nil)
	updated, _ := h.Store.GetByID(r.Context(), id)
	h.writeJSON(w, http.StatusOK, h.scimUserFromStore(r.Context(), updated))
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "invalidValue", "User id required")
		return
	}
	if err := h.Store.DeleteUser(r.Context(), id); err != nil {
		h.writeError(w, http.StatusInternalServerError, "internalError", err.Error())
		return
	}
	audit.LogUserChange("scim_delete", id, true, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request) {
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	startIndex, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	if count <= 0 {
		count = 100
	}
	if startIndex <= 0 {
		startIndex = 1
	}

	roles, err := h.Store.ListRoles(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internalError", err.Error())
		return
	}

	total := len(roles)
	offset := startIndex - 1
	end := offset + count
	if offset >= total {
		offset = 0
		end = 0
	} else if end > total {
		end = total
	}

	resources := make([]interface{}, 0)
	for i := offset; i < end && i < len(roles); i++ {
		r := &roles[i]
		resources = append(resources, &Group{
			Schemas:     []string{GroupSchema},
			ID:          r.ID,
			DisplayName: r.Name,
			Meta: &Meta{
				ResourceType: "Group",
				Location:      h.IssuerURL + "/scim/v2/Groups/" + r.ID,
			},
		})
	}

	h.writeJSON(w, http.StatusOK, ListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: total,
		ItemsPerPage: len(resources),
		StartIndex:   startIndex,
		Resources:    resources,
	})
}

func (h *Handler) resourceTypes(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC().Format(time.RFC3339)
	resources := []ResourceType{
		{
			Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			ID:       "User",
			Name:     "User",
			Endpoint: "/scim/v2/Users",
			Schema:   UserSchema,
			Meta:     &Meta{LastModified: parseTime(now)},
		},
		{
			Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			ID:       "Group",
			Name:     "Group",
			Endpoint: "/scim/v2/Groups",
			Schema:   GroupSchema,
			Meta:     &Meta{LastModified: parseTime(now)},
		},
	}
	resp := ListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: 2,
		Resources:    []interface{}{resources[0], resources[1]},
	}
	h.writeJSON(w, http.StatusOK, resp)
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func (h *Handler) schemas(w http.ResponseWriter, r *http.Request) {
	userAttrs := []SchemaAttr{
		{Name: "userName", Type: "string", Required: true, Mutability: "readWrite", Returned: "always"},
		{Name: "name", Type: "complex", Mutability: "readWrite", Returned: "default"},
		{Name: "emails", Type: "complex", Mutability: "readWrite", Returned: "default"},
		{Name: "active", Type: "boolean", Mutability: "readWrite", Returned: "default"},
	}
	resources := []Schema{
		{
			Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			ID:          UserSchema,
			Name:        "User",
			Description: "User schema",
			Attributes:  userAttrs,
		},
		{
			Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			ID:          GroupSchema,
			Name:        "Group",
			Description: "Group schema (maps to roles)",
			Attributes: []SchemaAttr{
				{Name: "displayName", Type: "string", Mutability: "readOnly", Returned: "always"},
			},
		},
	}
	resp := ListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: 2,
		Resources:    []interface{}{resources[0], resources[1]},
	}
	h.writeJSON(w, http.StatusOK, resp)
}
