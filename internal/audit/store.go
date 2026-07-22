package audit

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/jmadler/auth2/internal/store"
)

// AuditStore is the interface for persisting audit events.
type AuditStore interface {
	Append(ctx context.Context, event Event) error
}

var (
	storeMu sync.Mutex
	auditStore AuditStore
)

// SetStore configures the audit store. When nil, uses stdout.
func SetStore(s AuditStore) {
	storeMu.Lock()
	defer storeMu.Unlock()
	auditStore = s
}

func getStore() AuditStore {
	storeMu.Lock()
	defer storeMu.Unlock()
	return auditStore
}

// StdoutStore writes audit events to stdout (default for dev).
type StdoutStore struct {
	logger *log.Logger
}

// NewStdoutStore returns a store that writes to stdout.
func NewStdoutStore() *StdoutStore {
	return &StdoutStore{logger: log.New(os.Stdout, "[audit] ", log.LstdFlags)}
}

func (s *StdoutStore) Append(ctx context.Context, event Event) error {
	b, _ := json.Marshal(event)
	s.logger.Println(string(b))
	return nil
}

// DBStore persists audit events to the database via the main store.
type DBStore struct {
	st store.Store
}

// NewDBStore returns a store that writes to the database.
func NewDBStore(st store.Store) *DBStore {
	return &DBStore{st: st}
}

func (s *DBStore) Append(ctx context.Context, event Event) error {
	payload, _ := json.Marshal(event)
	return s.st.AppendLog(ctx, event.Type, event.UserID, event.ClientID, string(payload))
}
