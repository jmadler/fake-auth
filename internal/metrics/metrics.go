package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AuthRequests counts /authorize requests by outcome.
	AuthRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fake_auth_authorize_requests_total",
		Help: "Total number of /authorize requests",
	}, []string{"outcome"}) // outcome: success, login_required, access_denied, error

	// TokenRequests counts /oauth/token requests by grant_type and outcome.
	TokenRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fake_auth_token_requests_total",
		Help: "Total number of token requests",
	}, []string{"grant_type", "outcome"})

	// LoginAttempts counts login attempts by outcome.
	LoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "fake_auth_login_attempts_total",
		Help: "Total number of login attempts",
	}, []string{"outcome"}) // outcome: success, failed

	// Signups counts user signups.
	Signups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "fake_auth_signups_total",
		Help: "Total number of user signups",
	})
)
