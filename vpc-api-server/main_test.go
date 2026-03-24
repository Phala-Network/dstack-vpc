package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestBuildSignedPayload(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		path     string
		query    string
		body     []byte
		expected string
	}{
		{
			name:     "no query no body",
			method:   "GET",
			path:     "/admin/nonce",
			expected: "GET:/admin/nonce",
		},
		{
			name:     "with query",
			method:   "GET",
			path:     "/admin/nodes",
			query:    "page=1&size=2",
			expected: "GET:/admin/nodes?page=1&size=2",
		},
		{
			name:     "with body",
			method:   "POST",
			path:     "/api/v1/node",
			body:     []byte(`{"foo":"bar"}`),
			expected: `POST:/api/v1/node:{"foo":"bar"}`,
		},
		{
			name:     "query and body",
			method:   "POST",
			path:     "/api/v1/node",
			query:    "force=true",
			body:     []byte("payload"),
			expected: "POST:/api/v1/node?force=true:payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(buildSignedPayload(tt.method, tt.path, tt.query, tt.body))
			if got != tt.expected {
				t.Fatalf("buildSignedPayload() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestShouldSkipAppAuth(t *testing.T) {
	cases := map[string]bool{
		"/health":               true,
		"/admin/allowlist":      true,
		"/api/v1/node":          true,
		"/api/v1/node/123/tags": true,
		"/api/register":         false,
		"/some/other":           false,
	}

	for path, expected := range cases {
		if got := shouldSkipAppAuth(path); got != expected {
			t.Fatalf("shouldSkipAppAuth(%q) = %v, want %v", path, got, expected)
		}
	}
}

func TestReadRequestBodyLimited(t *testing.T) {
	body := bytes.Repeat([]byte("a"), 10)
	got, err := readRequestBodyLimited(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("readRequestBodyLimited unexpected error: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("readRequestBodyLimited returned unexpected body")
	}

	_, err = readRequestBodyLimited(bytes.NewReader(body), 5)
	if !errors.Is(err, errRequestBodyTooLarge) {
		t.Fatalf("expected errRequestBodyTooLarge, got %v", err)
	}
}

func TestAuthorizeAdminRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		state, c, _, payload, _, _ := newAuthorizedContext(t, nil)
		if !state.authorizeAdminRequest(c, payload) {
			t.Fatalf("expected authorization success")
		}
	})

	t.Run("missing bearer header", func(t *testing.T) {
		state, c, w, payload, _, _ := newAuthorizedContext(t, nil)
		c.Request.Header.Del("Authorization")
		if state.authorizeAdminRequest(c, payload) {
			t.Fatalf("expected authorization failure")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("missing nonce header", func(t *testing.T) {
		state, c, w, payload, _, _ := newAuthorizedContext(t, nil)
		c.Request.Header.Del("X-Nonce")
		if state.authorizeAdminRequest(c, payload) {
			t.Fatalf("expected authorization failure")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("missing timestamp header", func(t *testing.T) {
		state, c, w, payload, _, _ := newAuthorizedContext(t, nil)
		c.Request.Header.Del("X-UTC-Timestamp")
		if state.authorizeAdminRequest(c, payload) {
			t.Fatalf("expected authorization failure")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("invalid timestamp format", func(t *testing.T) {
		state, c, w, payload, _, _ := newAuthorizedContext(t, nil)
		c.Request.Header.Set("X-UTC-Timestamp", "not-a-timestamp")
		if state.authorizeAdminRequest(c, payload) {
			t.Fatalf("expected authorization failure")
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("timestamp skew too large", func(t *testing.T) {
		ts := time.Now().UTC().Add(-(maxTimestampSkew + time.Second))
		opts := &authContextOptions{timestamp: ts}
		state, c, w, payload, _, _ := newAuthorizedContext(t, opts)
		if state.authorizeAdminRequest(c, payload) {
			t.Fatalf("expected authorization failure")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		state, c, w, payload, nonce, timestamp := newAuthorizedContext(t, nil)
		otherKey, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("failed to create key: %v", err)
		}
		badSig := signTestPayload(t, otherKey, nonce, timestamp, payload)
		c.Request.Header.Set("Authorization", "Bearer "+badSig)
		if state.authorizeAdminRequest(c, payload) {
			t.Fatalf("expected authorization failure")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("nonce not found", func(t *testing.T) {
		opts := &authContextOptions{skipStoreNonce: true}
		state, c, w, payload, _, _ := newAuthorizedContext(t, opts)
		if state.authorizeAdminRequest(c, payload) {
			t.Fatalf("expected authorization failure")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}

// Helpers

type authContextOptions struct {
	timestamp      time.Time
	skipStoreNonce bool
}

func newAuthorizedContext(t *testing.T, opts *authContextOptions) (*AppState, *gin.Context, *httptest.ResponseRecorder, []byte, string, string) {
	state, priv := newTestAppState(t)
	payload := []byte("payload")
	nonce := fmt.Sprintf("nonce-%d", time.Now().UnixNano())
	ts := time.Now().UTC()
	storeNonce := true

	if opts != nil {
		if !opts.timestamp.IsZero() {
			ts = opts.timestamp
		}
		if opts.skipStoreNonce {
			storeNonce = false
		}
	}
	if storeNonce {
		if err := state.storeNonce(nonce); err != nil {
			t.Fatalf("failed to store nonce: %v", err)
		}
	}

	timestamp := ts.Format(time.RFC3339)
	sig := signTestPayload(t, priv, nonce, timestamp, payload)

	c, w := newTestContext()
	c.Request.Header.Set("Authorization", "Bearer "+sig)
	c.Request.Header.Set("X-Nonce", nonce)
	c.Request.Header.Set("X-UTC-Timestamp", timestamp)

	return state, c, w, payload, nonce, timestamp
}

func newTestAppState(t *testing.T) (*AppState, *ecdsa.PrivateKey) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	addr := crypto.PubkeyToAddress(priv.PublicKey).Hex()

	dir := t.TempDir()
	opts := badger.DefaultOptions(filepath.Join(dir, "nonce.db"))
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatalf("failed to open badger DB: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
	})

	state := &AppState{
		config:  Config{OwnerAddress: addr},
		nonceDB: db,
	}
	return state, priv
}

func newTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/admin/test", nil)
	return c, w
}

func signTestPayload(t *testing.T, key *ecdsa.PrivateKey, nonce, timestamp string, payload []byte) string {
	message := nonce + ":" + timestamp
	if len(payload) > 0 {
		message += ":" + string(payload)
	}
	prefixed := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := crypto.Keccak256Hash([]byte(prefixed))
	sig, err := crypto.Sign(hash.Bytes(), key)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}
	return "0x" + hex.EncodeToString(sig)
}
