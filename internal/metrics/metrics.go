package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AuthRequests counts /authorize requests by outcome.
	AuthRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth2_authorize_requests_total",
		Help: "Total number of /authorize requests",
	}, []string{"outcome"}) // outcome: success, login_required, access_denied, error

	// TokenRequests counts /oauth/token requests by grant_type and outcome.
	TokenRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth2_token_requests_total",
		Help: "Total number of token requests",
	}, []string{"grant_type", "outcome"})

	// LoginAttempts counts login attempts by outcome.
	LoginAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth2_login_attempts_total",
		Help: "Total number of login attempts",
	}, []string{"outcome"}) // outcome: success, failed

	// Signups counts user signups.
	Signups = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth2_signups_total",
		Help: "Total number of user signups",
	})

	// RequestDurationSeconds is a histogram of request latencies by path and method.
	RequestDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "auth2_request_duration_seconds",
		Help:    "Request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"path", "method"})

	// ActiveSessions is a gauge of current active sessions (when session store exposes count).
	ActiveSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "auth2_active_sessions",
		Help: "Number of active sessions",
	})
)

// ObserveRequestDuration records the duration of a request. Call at end of request.
func ObserveRequestDuration(path, method string, d time.Duration) {
	RequestDurationSeconds.WithLabelValues(path, method).Observe(d.Seconds())
}
