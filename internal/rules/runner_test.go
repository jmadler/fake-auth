package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRun_emptyDir(t *testing.T) {
	dir := t.TempDir()
	r := NewRunner(dir)
	user := &User{UserID: "u1", Nickname: "original"}
	ctx := &Context{ClientID: "c1"}

	out, err := r.Run(user, ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Nickname != "original" {
		t.Errorf("expected user unchanged, got nickname %q", out.Nickname)
	}
}

func TestRun_nilRunner(t *testing.T) {
	user := &User{UserID: "u1", Nickname: "original"}
	ctx := &Context{ClientID: "c1"}

	var r *Runner
	out, err := r.Run(user, ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Nickname != "original" {
		t.Errorf("expected user unchanged, got nickname %q", out.Nickname)
	}
}

func TestRun_modifiesUser(t *testing.T) {
	dir := t.TempDir()
	ruleContent := `user.nickname = "modified"; callback(null, user, context);`
	if err := os.WriteFile(filepath.Join(dir, "rule.js"), []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	r := NewRunner(dir)
	user := &User{UserID: "u1", Nickname: "original"}
	ctx := &Context{ClientID: "c1"}

	out, err := r.Run(user, ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Nickname != "modified" {
		t.Errorf("expected nickname %q, got %q", "modified", out.Nickname)
	}
}

func TestRun_invalidJS(t *testing.T) {
	dir := t.TempDir()
	ruleContent := `syntax error {{{`
	if err := os.WriteFile(filepath.Join(dir, "bad.js"), []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	r := NewRunner(dir)
	user := &User{UserID: "u1"}
	ctx := &Context{}

	_, err := r.Run(user, ctx)
	if err == nil {
		t.Fatal("expected error for invalid JS")
	}
}
