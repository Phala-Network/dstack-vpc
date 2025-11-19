package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
)

type Config struct {
	OwnerAddress string // 管理员钱包地址
	DataDir      string
}

type NodeInfo struct {
	UUID        string  `json:"uuid"`
	Name        string  `json:"name"`
	NodeType    string  `json:"node_type"`
	TailscaleIP *string `json:"tailscale_ip"`
}

type BootstrapResponse struct {
	PreAuthKey string `json:"pre_auth_key"`
	SharedKey  string `json:"shared_key"`
	ServerURL  string `json:"server_url"`
}

type AppState struct {
	config       Config
	nodes        map[string]NodeInfo
	allowedApps  map[string]bool   // 动态 allowlist
	nodeAppMap   map[string]string // node_name -> app_id mapping
	mutex        sync.RWMutex
	sharedKey    string
	ServerURL    string
	meshURL      string
	headscaleURL string
	nonceDB      *badger.DB
	httpClient   *http.Client
}

// Request for allowlist operations (由管理员签名授权)
type AllowlistRequest struct {
	AppID string `json:"app_id"`
}

// Nonce challenge response
type NonceResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expires_at"`
	Owner     string `json:"owner"`
}

const (
	nonceTTL         = 24 * time.Hour
	maxTimestampSkew = 30 * time.Second
)

type DstackInfo struct {
	AppID string `json:"app_id"`
}

type GatewayInfo struct {
	GatewayDomain string `json:"gateway_domain"`
}

// Generate a random nonce
func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func openNonceDB(dataDir string) (*badger.DB, error) {
	path := filepath.Join(dataDir, "nonce.db")
	opts := badger.DefaultOptions(path)
	opts.Logger = nil // reduce noise in logs
	return badger.Open(opts)
}

func (s *AppState) storeNonce(nonce string) error {
	return s.nonceDB.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(nonce), []byte{1}).WithTTL(nonceTTL)
		return txn.SetEntry(e)
	})
}

func (s *AppState) validateNonce(nonce string) error {
	return s.nonceDB.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(nonce))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return fmt.Errorf("nonce not found or expired")
		}
		return err
	})
}

// verifySignedPayload checks that the provided signature (Authorization Bearer)
// is produced by the owner key over nonce[:payload]. Payload is optional.
func (s *AppState) verifySignedPayload(nonce, timestamp, signature string, payload []byte) error {
	if nonce == "" {
		return fmt.Errorf("missing nonce")
	}
	if signature == "" {
		return fmt.Errorf("missing signature")
	}

	if err := s.validateNonce(nonce); err != nil {
		return err
	}

	message := nonce + ":" + timestamp
	if len(payload) > 0 {
		message += ":" + string(payload)
	}

	sigBytes, err := hex.DecodeString(strings.TrimPrefix(signature, "0x"))
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}
	if len(sigBytes) != 65 {
		return fmt.Errorf("invalid signature length")
	}
	if sigBytes[64] >= 27 {
		sigBytes[64] -= 27
	}

	prefixed := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	messageHash := crypto.Keccak256Hash([]byte(prefixed))

	pubKey, err := crypto.SigToPub(messageHash.Bytes(), sigBytes)
	if err != nil {
		return fmt.Errorf("failed to recover public key: %w", err)
	}

	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	if !strings.EqualFold(recoveredAddr.Hex(), s.config.OwnerAddress) {
		return fmt.Errorf("signer %s is not owner %s", recoveredAddr.Hex(), s.config.OwnerAddress)
	}

	return nil
}

func (s *AppState) authorizeAdminRequest(c *gin.Context, payload []byte) bool {
	authHeader := c.GetHeader("Authorization")
	if len(authHeader) < 7 || !strings.EqualFold(authHeader[:7], "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer signature"})
		return false
	}

	nonce := c.GetHeader("X-Nonce")
	if nonce == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing nonce"})
		return false
	}

	timestamp := c.GetHeader("X-UTC-Timestamp")
	if timestamp == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing timestamp"})
		return false
	}

	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid timestamp format"})
		return false
	}

	now := time.Now().UTC()
	if now.Sub(ts) > maxTimestampSkew || ts.Sub(now) > maxTimestampSkew {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "timestamp skew too large"})
		return false
	}

	signature := strings.TrimSpace(authHeader[7:])

	if err := s.verifySignedPayload(nonce, timestamp, signature, payload); err != nil {
		log.Printf("Admin authorization failed: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature", "details": err.Error()})
		return false
	}

	return true
}

// ============================================================================
// Admin authentication (nonce + signature)
// ============================================================================

// Get nonce for admin session
func (s *AppState) HandleGetNonce(c *gin.Context) {
	nonce, err := generateNonce()
	if err != nil {
		log.Printf("Failed to generate nonce: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate nonce"})
		return
	}

	if err := s.storeNonce(nonce); err != nil {
		log.Printf("Failed to store nonce: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue nonce"})
		return
	}

	expiresAt := time.Now().Add(nonceTTL).Format(time.RFC3339)
	c.JSON(200, NonceResponse{
		Nonce:     nonce,
		ExpiresAt: expiresAt,
		Owner:     s.config.OwnerAddress,
	})
}

// ============================================================================
// Allowlist Management (需要管理员签名)
// ============================================================================

func (s *AppState) HandleCreateAllowlist(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if !s.authorizeAdminRequest(c, body) {
		return
	}

	var req AllowlistRequest
	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if req.AppID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app_id is required"})
		return
	}

	// Apply action
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.allowedApps[req.AppID] = true
	log.Printf("Added app %s to allowlist", req.AppID)

	// Persist changes
	if err := s.saveAllowlist(); err != nil {
		log.Printf("Warning: failed to save allowlist: %v", err)
	}

	c.JSON(200, gin.H{
		"success": true,
		"app_id":  req.AppID,
	})
}

func (s *AppState) HandleGetAllowlist(c *gin.Context) {
	payload := []byte("GET:/admin/allowlist")
	if !s.authorizeAdminRequest(c, payload) {
		return
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	apps := make([]string, 0, len(s.allowedApps))
	for appID := range s.allowedApps {
		apps = append(apps, appID)
	}

	c.JSON(200, gin.H{
		"allowed_apps": apps,
		"count":        len(apps),
		"owner":        s.config.OwnerAddress,
	})
}

func (s *AppState) HandleDeleteAllowlist(c *gin.Context) {
	appID := strings.TrimSpace(c.Param("app_id"))
	if appID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing app_id"})
		return
	}

	payload := []byte(fmt.Sprintf("DELETE:/admin/allowlist/%s", appID))
	if !s.authorizeAdminRequest(c, payload) {
		return
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.allowedApps[appID]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}

	delete(s.allowedApps, appID)
	if err := s.saveAllowlist(); err != nil {
		log.Printf("Warning: failed to save allowlist: %v", err)
	}

	log.Printf("Removed app %s from allowlist", appID)
	c.JSON(200, gin.H{
		"success": true,
		"app_id":  appID,
	})
}

func (s *AppState) HandleGetNodes(c *gin.Context) {
	payload := []byte("GET:/admin/nodes")
	if !s.authorizeAdminRequest(c, payload) {
		return
	}

	apiKey, err := s.getAPIKey()
	if err != nil {
		log.Printf("Failed to load headscale API key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "headscale API key not available"})
		return
	}

	// 注入内部使用的 API Key 后重用现有逻辑
	c.Request.Header.Set("Authorization", "Bearer "+apiKey)
	s.HandleProxyNodeList(c)
}

// Persist allowlist to disk
func (s *AppState) saveAllowlist() error {
	if s.config.DataDir == "" {
		return nil
	}

	os.MkdirAll(s.config.DataDir, 0755)
	filePath := fmt.Sprintf("%s/allowlist.json", s.config.DataDir)

	data := map[string]interface{}{
		"allowed_apps": s.allowedApps,
		"node_app_map": s.nodeAppMap,
		"updated_at":   time.Now().Format(time.RFC3339),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, jsonData, 0644)
}

// Load allowlist from disk
func (s *AppState) loadAllowlist() {
	if s.config.DataDir == "" {
		return
	}

	filePath := fmt.Sprintf("%s/allowlist.json", s.config.DataDir)
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("No existing allowlist found, starting fresh")
		return
	}

	var saved struct {
		AllowedApps map[string]bool   `json:"allowed_apps"`
		NodeAppMap  map[string]string `json:"node_app_map"`
	}

	if err := json.Unmarshal(data, &saved); err != nil {
		log.Printf("Failed to parse allowlist: %v", err)
		return
	}

	if saved.AllowedApps != nil {
		s.allowedApps = saved.AllowedApps
	} else {
		s.allowedApps = make(map[string]bool)
	}
	if saved.NodeAppMap != nil {
		s.nodeAppMap = saved.NodeAppMap
	} else {
		s.nodeAppMap = make(map[string]string)
	}
	log.Printf("Loaded %d apps from allowlist, %d node mappings", len(s.allowedApps), len(s.nodeAppMap))
}

// ============================================================================
// Headscale Integration
// ============================================================================

func getAppIDFromDstackMesh(meshURL string, client *http.Client) (string, error) {
	resp, err := client.Get(fmt.Sprintf("%s/info", meshURL))
	if err != nil {
		return "", fmt.Errorf("failed to get app info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dstack-mesh Info returned status %d", resp.StatusCode)
	}

	var info DstackInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("failed to decode app info: %w", err)
	}

	return info.AppID, nil
}

func getGatewayDomainFromDstackMesh(meshURL string, client *http.Client) (string, error) {
	resp, err := client.Get(fmt.Sprintf("%s/gateway", meshURL))
	if err != nil {
		return "", fmt.Errorf("failed to get gateway info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dstack-mesh Gateway returned status %d", resp.StatusCode)
	}

	var info GatewayInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("failed to decode gateway info: %w", err)
	}

	return info.GatewayDomain, nil
}

func buildHeadscaleURL(meshURL string, client *http.Client) string {
	if url := os.Getenv("VPC_SERVER_URL"); url != "" {
		return url
	}

	var appID, gatewayDomain string
	var err error

	for i := 0; i < 30; i++ {
		appID, err = getAppIDFromDstackMesh(meshURL, client)
		if err == nil {
			break
		}
		log.Printf("Waiting for dstack-mesh to be ready... (%d/30)", i+1)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		log.Printf("Failed to get app_id after retries: %v, falling back to default", err)
		return "http://headscale:8080"
	}

	gatewayDomain, err = getGatewayDomainFromDstackMesh(meshURL, client)
	if err != nil {
		log.Printf("Failed to get gateway_domain: %v, falling back to default", err)
		return "http://headscale:8080"
	}

	return fmt.Sprintf("https://%s-8080.%s", appID, gatewayDomain)
}

func (s *AppState) isAppAllowed(appID string) bool {
	s.mutex.RLock()
	allowed := s.allowedApps[appID]
	s.mutex.RUnlock()
	return allowed
}

type HeadscaleNode struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	User        string   `json:"user"`
	IPAddresses []string `json:"ipAddresses"`
	Online      bool     `json:"online"`
}

type PreAuthKeyRequest struct {
	User       string `json:"user"`
	Reusable   bool   `json:"reusable"`
	Ephemeral  bool   `json:"ephemeral"`
	Expiration string `json:"expiration"`
}

type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type UsersResponse struct {
	Users []User `json:"users"`
}

type PreAuthKeyData struct {
	Key string `json:"key"`
}

type PreAuthKeyResponse struct {
	PreAuthKey PreAuthKeyData `json:"preAuthKey"`
}

func (s *AppState) getAPIKey() (string, error) {
	if apiKey := os.Getenv("HEADSCALE_API_KEY"); apiKey != "" {
		return apiKey, nil
	}
	return "", fmt.Errorf("HEADSCALE_API_KEY is not set")
}

func (s *AppState) getUserID(username string) (string, error) {
	apiKey, err := s.getAPIKey()
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("GET", s.headscaleURL+"/api/v1/user", nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("headscale API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("headscale API returned status %d: %s", resp.StatusCode, string(body))
	}

	var usersResp UsersResponse
	if err := json.NewDecoder(resp.Body).Decode(&usersResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	for _, user := range usersResp.Users {
		if user.Name == username {
			return user.ID, nil
		}
	}

	return "", fmt.Errorf("user %s not found", username)
}

func (s *AppState) generatePreAuthKey() (string, error) {
	apiKey, err := s.getAPIKey()
	if err != nil {
		return "", err
	}

	userID, err := s.getUserID("default")
	if err != nil {
		return "", fmt.Errorf("failed to get user ID: %w", err)
	}

	expiration := time.Now().Add(24 * time.Hour).Format(time.RFC3339)

	reqBody := PreAuthKeyRequest{
		User:       userID,
		Reusable:   true,
		Ephemeral:  false,
		Expiration: expiration,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", s.headscaleURL+"/api/v1/preauthkey", bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("headscale API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Pre-auth key creation failed with status %d: %s", resp.StatusCode, string(body))
		return "", fmt.Errorf("headscale API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("Pre-auth key API response: %s", string(body))

	var keyResp PreAuthKeyResponse
	if err := json.Unmarshal(body, &keyResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if keyResp.PreAuthKey.Key == "" {
		return "", fmt.Errorf("received empty pre-auth key")
	}

	return keyResp.PreAuthKey.Key, nil
}

func getOrCreateSharedKey() string {
	keyPath := "/data/shared_key"

	if keyBytes, err := os.ReadFile(keyPath); err == nil {
		key := strings.TrimSpace(string(keyBytes))
		log.Printf("Loaded existing shared key from %s", keyPath)
		return key
	}

	keyBytes := make([]byte, 64)
	if _, err := rand.Read(keyBytes); err != nil {
		log.Fatalf("Failed to generate shared key: %v", err)
	}
	sharedKey := base64.StdEncoding.EncodeToString(keyBytes)

	if err := os.MkdirAll("/data", 0755); err != nil {
		log.Printf("Warning: failed to create /data directory: %v", err)
	}

	if err := os.WriteFile(keyPath, []byte(sharedKey), 0600); err != nil {
		log.Printf("Warning: failed to save shared key to %s: %v", keyPath, err)
	} else {
		log.Printf("Generated and saved new shared key to %s", keyPath)
	}

	return sharedKey
}

// ============================================================================
// Headscale API Proxy
// ============================================================================

// 通用代理：转发请求到 headscale
func (s *AppState) HandleProxyHeadscale(c *gin.Context) {
	// 验证是否有 API Key（只有管理员可以访问）
	apiKey := c.GetHeader("Authorization")
	if !strings.HasPrefix(apiKey, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// 构造目标 URL
	targetURL := s.headscaleURL + c.Request.URL.Path
	if c.Request.URL.RawQuery != "" {
		targetURL += "?" + c.Request.URL.RawQuery
	}

	// 创建新请求
	req, err := http.NewRequest(c.Request.Method, targetURL, c.Request.Body)
	if err != nil {
		log.Printf("Failed to create proxy request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Proxy error"})
		return
	}

	// 复制 headers（特别是 Authorization）
	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// 发送请求
	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("Proxy request failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Headscale unavailable"})
		return
	}
	defer resp.Body.Close()

	// 复制响应 headers
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	// 读取并返回响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read proxy response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Proxy error"})
		return
	}

	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
}

// 特殊处理：Node List - 注入 app_id
func (s *AppState) HandleProxyNodeList(c *gin.Context) {
	// 验证 API Key
	apiKey := c.GetHeader("Authorization")
	if !strings.HasPrefix(apiKey, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// 请求 headscale API
	targetURL := s.headscaleURL + "/api/v1/node"
	if c.Request.URL.RawQuery != "" {
		targetURL += "?" + c.Request.URL.RawQuery
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal error"})
		return
	}

	req.Header.Set("Authorization", apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Printf("Headscale request failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "Headscale unavailable"})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal error"})
		return
	}

	// 如果不是 200，直接返回原始响应
	if resp.StatusCode != http.StatusOK {
		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
		return
	}

	// 解析 JSON
	var nodesResp struct {
		Nodes []map[string]interface{} `json:"nodes"`
	}

	if err := json.Unmarshal(body, &nodesResp); err != nil {
		log.Printf("Failed to parse nodes response: %v", err)
		// 返回原始响应
		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
		return
	}

	// 注入 app_id
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for i := range nodesResp.Nodes {
		nodeName, ok := nodesResp.Nodes[i]["name"].(string)
		if !ok {
			continue
		}

		// 查找对应的 app_id
		if appID, exists := s.nodeAppMap[nodeName]; exists {
			nodesResp.Nodes[i]["app_id"] = appID
		}
	}

	// 返回修改后的 JSON
	c.JSON(http.StatusOK, nodesResp)
}

func main() {
	meshURL := os.Getenv("DSTACK_MESH_URL")
	if meshURL == "" {
		log.Fatal("DSTACK_MESH_URL is not set")
	}

	headscaleURL := os.Getenv("HEADSCALE_INTERNAL_URL")
	if headscaleURL == "" {
		log.Fatal("HEADSCALE_INTERNAL_URL is not set")
	}

	ownerAddress := os.Getenv("OWNER_ADDRESS")
	if ownerAddress == "" {
		log.Fatal("OWNER_ADDRESS is required for allowlist management")
	}

	if !common.IsHexAddress(ownerAddress) {
		log.Fatalf("Invalid Ethereum address: %s", ownerAddress)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "/data"
	}

	config := Config{
		OwnerAddress: ownerAddress,
		DataDir:      dataDir,
	}

	nonceDB, err := openNonceDB(dataDir)
	if err != nil {
		log.Fatalf("Failed to open nonce database: %v", err)
	}
	defer nonceDB.Close()

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	sharedKey := getOrCreateSharedKey()
	serverURL := buildHeadscaleURL(meshURL, httpClient)
	log.Printf("Using Headscale URL: %s", serverURL)

	state := &AppState{
		config:       config,
		nodes:        make(map[string]NodeInfo),
		allowedApps:  make(map[string]bool),
		nodeAppMap:   make(map[string]string),
		mutex:        sync.RWMutex{},
		sharedKey:    sharedKey,
		ServerURL:    serverURL,
		meshURL:      meshURL,
		headscaleURL: headscaleURL,
		nonceDB:      nonceDB,
		httpClient:   httpClient,
	}

	// Load persisted allowlist
	state.loadAllowlist()

	log.Printf("VPC API Server starting")
	log.Printf("  Owner Address: %s", config.OwnerAddress)
	log.Printf("  Allowed Apps: %d", len(state.allowedApps))

	r := gin.Default()

	// ========================================================================
	// Middleware: Check app_id for node registration
	// ========================================================================
	r.Use(func(c *gin.Context) {
		// Skip auth for health and management endpoints
		if c.Request.URL.Path == "/health" ||
			strings.HasPrefix(c.Request.URL.Path, "/admin/") {
			c.Next()
			return
		}

		// Check app_id for node registration
		appID := c.GetHeader("x-dstack-app-id")
		if appID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		if !state.isAppAllowed(appID) {
			log.Printf("App %s is not in allowlist", appID)
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			c.Abort()
			return
		}

		c.Next()
	})

	// ========================================================================
	// Node Registration Endpoint
	// ========================================================================
	r.GET("/api/register", func(c *gin.Context) {
		instanceUUID := c.Query("instance_id")
		nodeName := c.Query("node_name")
		appID := c.GetHeader("x-dstack-app-id")

		if instanceUUID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameters"})
			return
		}

		preAuthKey, err := state.generatePreAuthKey()
		if err != nil {
			log.Printf("Failed to generate pre-auth key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate pre-auth key"})
			return
		}

		if nodeName == "" {
			nodeName = fmt.Sprintf("node-%s", instanceUUID)
		}

		nodeInfo := NodeInfo{
			UUID:        instanceUUID,
			Name:        nodeName,
			TailscaleIP: nil,
		}

		state.mutex.Lock()
		state.nodes[instanceUUID] = nodeInfo
		// 记录 node_name -> app_id 映射
		state.nodeAppMap[nodeName] = appID
		state.mutex.Unlock()

		// 持久化 node mapping
		if err := state.saveAllowlist(); err != nil {
			log.Printf("Warning: failed to save node mapping: %v", err)
		}

		response := BootstrapResponse{
			PreAuthKey: preAuthKey,
			SharedKey:  state.sharedKey,
			ServerURL:  state.ServerURL,
		}

		log.Printf("Bootstrap request from %s (%s) for app %s", nodeName, instanceUUID, appID)
		c.JSON(http.StatusOK, response)
	})

	// ========================================================================
	// Admin Endpoints (需要签名认证)
	// ========================================================================
	r.GET("/admin/nonce", state.HandleGetNonce)             // 获取 nonce
	r.POST("/admin/allowlist", state.HandleCreateAllowlist) // 添加 allowlist
	r.GET("/admin/allowlist", state.HandleGetAllowlist)     // 查看 allowlist
	r.DELETE("/admin/allowlist/:app_id", state.HandleDeleteAllowlist)
	r.GET("/admin/nodes", state.HandleGetNodes) // 查看节点列表

	// ========================================================================
	// Headscale API Proxy (需要 API Key 或 Admin 权限)
	// ========================================================================

	// 特殊处理：GET /api/v1/node - 注入 app_id
	r.GET("/api/v1/node", state.HandleProxyNodeList)

	// 通用代理：转发其他 /api/v1/... 请求到 headscale
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/v1/") {
			state.HandleProxyHeadscale(c)
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
	})

	// ========================================================================
	// Health Check
	// ========================================================================
	healthHandler := func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	}
	r.GET("/health", healthHandler)
	r.HEAD("/health", healthHandler)

	log.Printf("VPC API Server listening on port %s", port)
	r.Run(":" + port)
}
