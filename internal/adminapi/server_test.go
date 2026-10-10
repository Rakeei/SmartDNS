package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testToken = "0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T) (*Server, string, string, *int) {
	t.Helper()
	dir := t.TempDir()
	domains := filepath.Join(dir, "domains.txt")
	cidrs := filepath.Join(dir, "allowed_ips.txt")
	os.WriteFile(domains, []byte("example.com\n"), 0644)
	os.WriteFile(cidrs, []byte("203.0.113.5\n"), 0644)

	reloads := 0
	s := New(testToken, domains, cidrs, func() error { reloads++; return nil })
	return s, domains, cidrs, &reloads
}

func do(t *testing.T, s *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

func TestRejectsMissingOrWrongToken(t *testing.T) {
	s, _, _, _ := newTestServer(t)
	for _, tok := range []string{"", "wrong", testToken + "x"} {
		rec := do(t, s, http.MethodGet, "/v1/domains", tok, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: got %d, want 401", tok, rec.Code)
		}
	}
}

func TestListDomains(t *testing.T) {
	s, _, _, _ := newTestServer(t)
	rec := do(t, s, http.MethodGet, "/v1/domains", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	var out struct {
		Entries []string `json:"entries"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Entries) != 1 || out.Entries[0] != "example.com" {
		t.Fatalf("entries = %v", out.Entries)
	}
}

func TestAddDomainReloadsOnlyWhenNew(t *testing.T) {
	s, domains, _, reloads := newTestServer(t)

	rec := do(t, s, http.MethodPost, "/v1/domains", testToken, `{"value":"Adobe.com"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"added":true`) {
		t.Fatalf("first add: %d %s", rec.Code, rec.Body.String())
	}
	if *reloads != 1 {
		t.Fatalf("reloads = %d, want 1", *reloads)
	}
	data, _ := os.ReadFile(domains)
	if !strings.Contains(string(data), "adobe.com") {
		t.Fatalf("domain not persisted: %q", data)
	}

	rec = do(t, s, http.MethodPost, "/v1/domains", testToken, `{"value":"adobe.com"}`)
	if !strings.Contains(rec.Body.String(), `"added":false`) {
		t.Fatalf("duplicate add: %s", rec.Body.String())
	}
	if *reloads != 1 {
		t.Fatalf("duplicate triggered reload: %d", *reloads)
	}
}

func TestRejectsInvalidInput(t *testing.T) {
	s, domains, cidrs, reloads := newTestServer(t)
	cases := []struct{ path, body string }{
		{"/v1/domains", `{"value":"bad domain\nevil"}`},
		{"/v1/domains", `{"value":"-x.com"}`},
		{"/v1/domains", `{"value":""}`},
		{"/v1/ips", `{"value":"not-an-ip"}`},
		{"/v1/ips", `{"value":"10.0.0.0/99"}`},
		{"/v1/domains", `{"value":"a.com","extra":1}`},
		{"/v1/domains", `not json`},
	}
	for _, c := range cases {
		rec := do(t, s, http.MethodPost, c.path, testToken, c.body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s %s: got %d, want 400", c.path, c.body, rec.Code)
		}
	}
	if *reloads != 0 {
		t.Fatalf("invalid input triggered reload")
	}
	d, _ := os.ReadFile(domains)
	c, _ := os.ReadFile(cidrs)
	if strings.Contains(string(d), "evil") || strings.Contains(string(c), "not-an-ip") {
		t.Fatalf("invalid input was written to disk")
	}
}

func TestAddIPAcceptsCIDR(t *testing.T) {
	s, _, cidrs, _ := newTestServer(t)
	rec := do(t, s, http.MethodPost, "/v1/ips", testToken, `{"value":"198.51.100.0/24"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	data, _ := os.ReadFile(cidrs)
	if !strings.Contains(string(data), "198.51.100.0/24") {
		t.Fatalf("cidr not persisted")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	s, _, _, _ := newTestServer(t)
	rec := do(t, s, http.MethodDelete, "/v1/domains", testToken, "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestBodySizeLimited(t *testing.T) {
	s, _, _, _ := newTestServer(t)
	big := `{"value":"` + strings.Repeat("a", 8<<10) + `"}`
	rec := do(t, s, http.MethodPost, "/v1/domains", testToken, big)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: got %d", rec.Code)
	}
}

func TestAppendToFileWithoutTrailingNewline(t *testing.T) {
	s, domains, _, _ := newTestServer(t)
	os.WriteFile(domains, []byte("example.com"), 0644)
	rec := do(t, s, http.MethodPost, "/v1/domains", testToken, `{"value":"adobe.com"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	got, _ := readLinesForTest(domains)
	if len(got) != 2 || got[0] != "example.com" || got[1] != "adobe.com" {
		t.Fatalf("entries corrupted: %q", got)
	}
}

func TestReloadFailureRollsBackAndRetryReloads(t *testing.T) {
	dir := t.TempDir()
	domains := filepath.Join(dir, "domains.txt")
	cidrs := filepath.Join(dir, "allowed_ips.txt")
	os.WriteFile(domains, []byte("example.com\n"), 0644)
	os.WriteFile(cidrs, []byte(""), 0644)

	fail := true
	reloads := 0
	s := New(testToken, domains, cidrs, func() error {
		reloads++
		if fail {
			return os.ErrInvalid
		}
		return nil
	})

	rec := do(t, s, http.MethodPost, "/v1/domains", testToken, `{"value":"adobe.com"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("reload failure: got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), dir) {
		t.Fatalf("error leaks filesystem path: %s", rec.Body.String())
	}
	data, _ := os.ReadFile(domains)
	if strings.Contains(string(data), "adobe.com") {
		t.Fatalf("failed change left on disk")
	}

	fail = false
	rec = do(t, s, http.MethodPost, "/v1/domains", testToken, `{"value":"adobe.com"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"added":true`) {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body.String())
	}
	if reloads != 2 {
		t.Fatalf("reloads = %d, want 2", reloads)
	}
}

func TestIOErrorIsNot400(t *testing.T) {
	dir := t.TempDir()
	missingDir := filepath.Join(dir, "nope", "domains.txt")
	s := New(testToken, missingDir, filepath.Join(dir, "c.txt"), func() error { return nil })
	rec := do(t, s, http.MethodPost, "/v1/domains", testToken, `{"value":"adobe.com"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("io error: got %d, want 500", rec.Code)
	}
}

func readLinesForTest(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		out = append(out, l)
	}
	return out, nil
}
