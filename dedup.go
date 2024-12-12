package dedup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("dedup", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("dedup", httpcaddyfile.Before, "reverse_proxy")
}

type Middleware struct {
	MasterToken string `json:"master_token,omitempty"`

	logger        *zap.Logger
	cache         sync.Map
	cleanupTicker *time.Ticker
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.dedup",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	m.cleanupTicker = time.NewTicker(1 * time.Minute)
	go m.cleanup()
	return nil
}

func (m *Middleware) cleanup() {
	for range m.cleanupTicker.C {
		m.cache.Range(func(key, value interface{}) bool {
			if timestamp, ok := value.(time.Time); ok {
				if time.Since(timestamp) > 5*time.Minute {
					m.cache.Delete(key)
				}
			}
			return true
		})
	}
}

func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Method != http.MethodPost || r.URL.Path != "/discord/event" || r.Header.Get("User-Agent") == "Discord-Webhook/1.0 (+https://discord.com)" {
		return next.ServeHTTP(w, r)
	}

	if r.Header.Get("Authorization") != m.MasterToken {
		m.logger.Info("unauthorized: token mismatch")
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"detail":"Unauthorized"}`))
		return nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	r.Body = io.NopCloser(bytes.NewReader(body))

	hash := sha256.Sum256(body)
	hashStr := hex.EncodeToString(hash[:])

	if _, exists := m.cache.LoadOrStore(hashStr, time.Now()); exists {
		m.logger.Info("blocking duplicate event", zap.String("hash", hashStr))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("DUPLICATE_EVENT"))
		return nil
	}

	return next.ServeHTTP(w, r)
}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&m.MasterToken) {
			return d.ArgErr()
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}
