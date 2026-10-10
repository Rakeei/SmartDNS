// Package adminapi exposes a small, bearer-token-protected HTTPS API for
// listing and adding smart-routed domains and allowed client IPs/CIDRs, so a
// remote controller (the Cloudflare Worker bot) can manage a running
// smartdns instance without shell access to the host.
package adminapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"smartdns/internal/config"
)

const maxBodyBytes = 4 << 10

type Server struct {
	tokenHash   [32]byte
	domainsFile string
	cidrsFile   string
	reload      func() error

	// mu serializes writes so two concurrent adds can't both pass the
	// duplicate check and append the same entry twice.
	mu  sync.Mutex
	mux *http.ServeMux
}

func New(token, domainsFile, cidrsFile string, reload func() error) *Server {
	s := &Server{
		tokenHash:   sha256.Sum256([]byte(token)),
		domainsFile: domainsFile,
		cidrsFile:   cidrsFile,
		reload:      reload,
		mux:         http.NewServeMux(),
	}
	s.mux.HandleFunc("/v1/domains", s.auth(s.domains))
	s.mux.HandleFunc("/v1/ips", s.auth(s.ips))
	return s
}

// ListenAndServeTLS serves the API over HTTPS. Timeouts are set so slow or
// stalled clients can't tie up connections indefinitely.
func (s *Server) ListenAndServeTLS(addr, certFile, keyFile string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return srv.ListenAndServeTLS(certFile, keyFile)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, prefix) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		got := sha256.Sum256([]byte(strings.TrimPrefix(h, prefix)))
		if subtle.ConstantTimeCompare(got[:], s.tokenHash[:]) != 1 {
			log.Printf("admin api: rejected request from %s", r.RemoteAddr)
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

type entryRequest struct {
	Value string `json:"value"`
}

type addResponse struct {
	Added bool   `json:"added"`
	Value string `json:"value"`
}

func (s *Server) domains(w http.ResponseWriter, r *http.Request) {
	s.listOrAdd(w, r, s.domainsFile, config.NormalizeDomain, func(v string) (bool, error) {
		return config.AppendDomain(s.domainsFile, v)
	})
}

func (s *Server) ips(w http.ResponseWriter, r *http.Request) {
	s.listOrAdd(w, r, s.cidrsFile, strings.TrimSpace, func(v string) (bool, error) {
		return config.AppendCIDR(s.cidrsFile, v)
	})
}

func (s *Server) listOrAdd(w http.ResponseWriter, r *http.Request, file string,
	normalize func(string) string, add func(string) (bool, error)) {
	switch r.Method {
	case http.MethodGet:
		entries, err := config.ReadList(file)
		if err != nil {
			log.Printf("admin api: read list: %v", err)
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": entries})

	case http.MethodPost:
		var req entryRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		val := normalize(req.Value)

		s.mu.Lock()
		defer s.mu.Unlock()

		added, err := add(val)
		if err != nil {
			if errors.Is(err, config.ErrInvalidEntry) {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			log.Printf("admin api: write list: %v", err)
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		if added {
			if err := s.reload(); err != nil {
				// Roll the entry back so a retry actually re-attempts the reload
				// instead of being reported as a duplicate.
				if rbErr := config.RemoveEntry(file, val); rbErr != nil {
					log.Printf("admin api: rollback failed, entry %q remains on disk: %v", val, rbErr)
				}
				log.Printf("admin api: reload failed, change for %q rolled back: %v", val, err)
				writeErr(w, http.StatusInternalServerError, "config reload failed; change was not applied")
				return
			}
			log.Printf("admin api: added %q and reloaded", val)
		}
		writeJSON(w, http.StatusOK, addResponse{Added: added, Value: val})

	default:
		w.Header().Set("Allow", "GET, POST")
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
