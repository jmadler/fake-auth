package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dop251/goja"
)

type User struct {
	UserID            string                 `json:"user_id"`
	Email             string                 `json:"email"`
	EmailVerified     bool                   `json:"email_verified"`
	Name              string                 `json:"name"`
	Nickname          string                 `json:"nickname"`
	UserMetadata      map[string]interface{} `json:"user_metadata"`
	AppMetadata       map[string]interface{} `json:"app_metadata"`
	IDTokenClaims     map[string]interface{} `json:"id_token_claims"`
	AccessTokenClaims map[string]interface{} `json:"access_token_claims"`
}

type Context struct {
	ClientID    string
	ClientName  string
	Connection  string
	Protocol    string
	RedirectURI string
}

type Runner struct {
	dir string
}

func NewRunner(rulesDir string) *Runner {
	if rulesDir == "" {
		return nil
	}
	return &Runner{dir: rulesDir}
}

func (r *Runner) Run(user *User, ctx *Context) (*User, error) {
	if r == nil || r.dir == "" {
		return user, nil
	}
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return user, nil
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".js") {
			continue
		}
		path := filepath.Join(r.dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		user, err = r.runRule(string(b), user, ctx)
		if err != nil {
			return user, fmt.Errorf("rule %s: %w", e.Name(), err)
		}
	}
	return user, nil
}

func (r *Runner) runRule(script string, user *User, ctx *Context) (*User, error) {
	vm := goja.New()
	userMap := userToMap(user)
	ctxMap := contextToMap(ctx)
	var resultUser map[string]interface{}
	callback := func(caller goja.FunctionCall) goja.Value {
		if len(caller.Arguments) >= 2 {
			obj := caller.Argument(1)
			if obj != nil && obj != goja.Undefined() {
				if o, ok := obj.Export().(map[string]interface{}); ok {
					resultUser = o
				}
			}
		}
		return goja.Undefined()
	}
	vm.Set("user", userMap)
	vm.Set("context", ctxMap)
	vm.Set("callback", callback)
	trimmed := strings.TrimSpace(script)
	if len(trimmed) > 8 && trimmed[:8] == "function" {
		_, err := vm.RunString("(" + script + ")(user, context, callback);")
		if err != nil {
			return user, err
		}
	} else {
		_, err := vm.RunString("(function(u,c,cb){ " + script + " })(user,context,callback);")
		if err != nil {
			return user, err
		}
	}
	if resultUser != nil {
		return mapToUser(resultUser), nil
	}
	return user, nil
}

func userToMap(u *User) map[string]interface{} {
	m := map[string]interface{}{
		"user_id":             u.UserID,
		"email":               u.Email,
		"email_verified":      u.EmailVerified,
		"name":                u.Name,
		"nickname":            u.Nickname,
		"user_metadata":       u.UserMetadata,
		"app_metadata":        u.AppMetadata,
		"id_token_claims":     u.IDTokenClaims,
		"access_token_claims": u.AccessTokenClaims,
	}
	if u.UserMetadata == nil {
		m["user_metadata"] = map[string]interface{}{}
	}
	if u.AppMetadata == nil {
		m["app_metadata"] = map[string]interface{}{}
	}
	if u.IDTokenClaims == nil {
		m["id_token_claims"] = map[string]interface{}{}
	}
	if u.AccessTokenClaims == nil {
		m["access_token_claims"] = map[string]interface{}{}
	}
	return m
}

func contextToMap(c *Context) map[string]interface{} {
	return map[string]interface{}{
		"clientID":     c.ClientID,
		"clientName":   c.ClientName,
		"connection":   c.Connection,
		"protocol":     c.Protocol,
		"redirect_uri": c.RedirectURI,
	}
}

func mapToUser(m map[string]interface{}) *User {
	u := &User{}
	if v, ok := m["user_id"].(string); ok {
		u.UserID = v
	}
	if v, ok := m["email"].(string); ok {
		u.Email = v
	}
	if v, ok := m["email_verified"].(bool); ok {
		u.EmailVerified = v
	}
	if v, ok := m["name"].(string); ok {
		u.Name = v
	}
	if v, ok := m["nickname"].(string); ok {
		u.Nickname = v
	}
	if v, ok := m["user_metadata"].(map[string]interface{}); ok {
		u.UserMetadata = v
	}
	if v, ok := m["app_metadata"].(map[string]interface{}); ok {
		u.AppMetadata = v
	}
	if v, ok := m["id_token_claims"].(map[string]interface{}); ok {
		u.IDTokenClaims = v
	}
	if v, ok := m["access_token_claims"].(map[string]interface{}); ok {
		u.AccessTokenClaims = v
	}
	return u
}

func (u *User) ToStoreFormat() (userID, email, name string) {
	userID = u.UserID
	email = u.Email
	if u.Name != "" {
		name = u.Name
	} else {
		name = u.Nickname
	}
	if name == "" {
		name = email
	}
	return
}
