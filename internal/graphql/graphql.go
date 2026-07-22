package graphql

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/graphql-go/graphql"
	"github.com/jmadler/auth2/internal/password"
	"github.com/jmadler/auth2/internal/store"
)

// Handler returns an http.Handler for the GraphQL test API.
// Only enabled when GRAPHQL_TEST_API_ENABLED=true.
// Requires Authorization: Bearer <ADMIN_API_KEY>.
func Handler(st store.Store) http.Handler {
	userType := graphql.NewObject(
		graphql.ObjectConfig{
			Name: "User",
			Fields: graphql.Fields{
				"id":    &graphql.Field{Type: graphql.String},
				"email": &graphql.Field{Type: graphql.String},
				"name":  &graphql.Field{Type: graphql.String},
			},
		},
	)

	createUserMutation := &graphql.Field{
		Type: userType,
		Args: graphql.FieldConfigArgument{
			"email":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			"password": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			"name":     &graphql.ArgumentConfig{Type: graphql.String},
		},
		Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			email, _ := p.Args["email"].(string)
			pass, _ := p.Args["password"].(string)
			name, _ := p.Args["name"].(string)

			if err := password.Validate(pass); err != nil {
				return nil, err
			}

			displayName := name
			if displayName == "" {
				displayName = email
				if i := strings.Index(email, "@"); i > 0 {
					displayName = email[:i]
				}
			}

			uid := "auth0|" + uuid.New().String()
			u := &store.User{
				ID:             uid,
				Email:          email,
				DisplayName:    displayName,
				EmailVerified:  true,
				OrganizationID: 1,
				EnterpriseID:   1,
				Role:           "user",
			}

			if err := st.CreateUser(p.Context, u, pass); err != nil {
				if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "duplicate") {
					return nil, err
				}
				return nil, err
			}

			return map[string]interface{}{
				"id":    u.ID,
				"email": u.Email,
				"name":  u.DisplayName,
			}, nil
		},
	}

	mutationType := graphql.NewObject(
		graphql.ObjectConfig{
			Name: "Mutation",
			Fields: graphql.Fields{
				"createUser": createUserMutation,
			},
		},
	)

	queryType := graphql.NewObject(
		graphql.ObjectConfig{
			Name: "Query",
			Fields: graphql.Fields{
				"ping": &graphql.Field{
					Type: graphql.String,
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						return "pong", nil
					},
				},
			},
		},
	)

	schema, err := graphql.NewSchema(graphql.SchemaConfig{
		Query:    queryType,
		Mutation: mutationType,
	})
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
			return
		}

		auth := r.Header.Get("Authorization")
		adminKey := os.Getenv("ADMIN_API_KEY")
		if adminKey == "" {
			adminKey = os.Getenv("MGMT_API_KEY")
		}
		if adminKey == "" || auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized", "message": "Authorization: Bearer <ADMIN_API_KEY> required"})
			return
		}
		tok := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if tok != adminKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized", "message": "Invalid ADMIN_API_KEY"})
			return
		}

		var req struct {
			Query     string                 `json:"query"`
			Variables map[string]interface{} `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid json"})
			return
		}
		if req.Query == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "query required"})
			return
		}

		result := graphql.Do(graphql.Params{
			Schema:         schema,
			RequestString:  req.Query,
			VariableValues: req.Variables,
			Context:        r.Context(),
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}

// IsEnabled returns true when GRAPHQL_TEST_API_ENABLED=true.
func IsEnabled() bool {
	return strings.ToLower(os.Getenv("GRAPHQL_TEST_API_ENABLED")) == "true"
}
