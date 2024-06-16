package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DanMolz/wiz-gadget/models"
	"github.com/DanMolz/wiz-gadget/pkg/wiz"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

const (
	crtFile       = "server.crt"
	keyFile       = "server.key"
	basicPrefix   = "Basic "
	bearerPrefix  = "Bearer "
	authHeaderKey = "Authorization"
)

var (
	serverConfig Config
	authConfig   AuthConfig
	apiConfig    APIConfig
	tokenManager TokenManager
	scanManager  ScanManager
)

type Config struct {
	Addr        string
	CertFile    string
	KeyFile     string
	IPWhitelist []string
}

type AuthConfig struct {
	Username     string
	Password     string
	Token        string
	ClientID     string
	ClientSecret string
	AuthURL      string
}

type APIConfig struct {
	APIURL string
}

type TokenManager struct {
	token     string
	expiresAt time.Time
	mu        sync.Mutex
}

type ScanManager struct {
	scanQueue      map[string][]ScanRequest
	scanStatus     map[string]bool
	monitorStarted map[string]bool
	monitorStop    map[string]chan struct{}
	mu             sync.Mutex
}

type ScanRequest struct {
	RequestID      string
	Payload        models.WebhookPayload
	ResponseWriter http.ResponseWriter
}

type OAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func init() {
	log.Println("Starting Wiz Gadget Server")

	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(); err != nil {
			log.Fatalf("Error loading .env file: %v", err)
		}
		log.Println(".env file loaded successfully")
	}

	serverConfig = Config{
		Addr:        ":8181",
		CertFile:    crtFile,
		KeyFile:     keyFile,
		IPWhitelist: getIPWhitelist(),
	}

	authConfig = AuthConfig{
		Username:     os.Getenv("BASIC_AUTH_USERNAME"),
		Password:     os.Getenv("BASIC_AUTH_PASSWORD"),
		Token:        os.Getenv("TOKEN_AUTH"),
		ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
		AuthURL:      os.Getenv("OAUTH_AUTH_URL"),
	}

	apiConfig = APIConfig{
		APIURL: os.Getenv("API_URL"),
	}

	scanManager = ScanManager{
		scanQueue:      make(map[string][]ScanRequest),
		scanStatus:     make(map[string]bool),
		monitorStarted: make(map[string]bool),
		monitorStop:    make(map[string]chan struct{}),
	}
}

func main() {
	if err := tokenManager.getOAuthToken(); err != nil {
		log.Fatalf("Failed to obtain Wiz OAuth token: %v", err)
	}

	http.HandleFunc("/webhook", WebhookHandler)

	server := &http.Server{
		Addr: serverConfig.Addr,
	}

	if _, err := os.Stat(serverConfig.CertFile); os.IsNotExist(err) {
		log.Fatalf("Certificate file %s not found, stopping application", serverConfig.CertFile)
	}
	if _, err := os.Stat(serverConfig.KeyFile); os.IsNotExist(err) {
		log.Fatalf("Key file %s not found, stopping application", serverConfig.KeyFile)
	}

	log.Printf("Wiz Gadget now listening on port %s", server.Addr)
	if err := server.ListenAndServeTLS(serverConfig.CertFile, serverConfig.KeyFile); err != nil {
		log.Fatalf("Failed to start HTTPS server: %v", err)
	}
}

func WebhookHandler(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()
	ip := getIPAddress(r)
	log.Printf("[%s] Request received from IP: %s", requestID, ip)

	if !isIPWhitelisted(ip) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		log.Printf("[%s] Forbidden request from IP: %s", requestID, ip)
		return
	}

	if !authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		log.Printf("[%s] Unauthorized request from IP: %s", requestID, ip)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		log.Printf("[%s] Method not allowed", requestID)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		log.Printf("[%s] Failed to read request body: %v", requestID, err)
		return
	}

	var payload models.WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		log.Printf("[%s] Invalid JSON: %v", requestID, err)
		return
	}

	if !isValidPayload(payload) {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		log.Printf("[%s] Invalid payload", requestID)
		return
	}

	logRequestDetails(requestID, payload)

	if err := scanManager.handleScanRequest(requestID, payload, w); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("[%s] Error while handling scan request: %v", requestID, err)
		return
	}
}

func getIPAddress(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}

	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func isIPWhitelisted(ip string) bool {
	for _, whitelistedIP := range serverConfig.IPWhitelist {
		if ip == whitelistedIP {
			return true
		}
	}
	return false
}

func authenticate(r *http.Request) bool {
	auth := r.Header.Get(authHeaderKey)
	if auth == "" {
		return false
	}

	if strings.HasPrefix(auth, basicPrefix) {
		decoded, err := base64.StdEncoding.DecodeString(auth[len(basicPrefix):])
		if err != nil {
			return false
		}
		creds := strings.SplitN(string(decoded), ":", 2)
		return len(creds) == 2 && creds[0] == authConfig.Username && creds[1] == authConfig.Password
	}

	if strings.HasPrefix(auth, bearerPrefix) {
		return auth[len(bearerPrefix):] == authConfig.Token
	}

	return false
}

func getIPWhitelist() []string {
	ipWhitelistEnv := os.Getenv("IP_WHITELIST")
	if ipWhitelistEnv == "" {
		log.Fatal("IP_WHITELIST environment variable is not set")
	}
	return strings.Split(ipWhitelistEnv, ",")
}

func isValidPayload(payload models.WebhookPayload) bool {
	return payload.Event.SubjectResource.AccountExternalID != ""
}

func (tm *TokenManager) getOAuthToken() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", authConfig.ClientID)
	data.Set("client_secret", authConfig.ClientSecret)
	data.Set("audience", "wiz-api")

	req, err := http.NewRequest("POST", authConfig.AuthURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to obtain Wiz OAuth token: %s", resp.Status)
	}

	log.Println("Successfully obtained Wiz OAuth token, status:", resp.Status)

	var tokenResp OAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return err
	}

	tm.token = tokenResp.AccessToken
	tm.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return nil
}

func (sm *ScanManager) handleScanRequest(requestID string, payload models.WebhookPayload, w http.ResponseWriter) error {
	tokenManager.mu.Lock()
	token := tokenManager.token
	expires := tokenManager.expiresAt
	tokenManager.mu.Unlock()

	// Refresh the token if it's about to expire
	if time.Until(expires) < 1*time.Minute {
		if err := tokenManager.getOAuthToken(); err != nil {
			return err
		}
		tokenManager.mu.Lock()
		token = tokenManager.token
		tokenManager.mu.Unlock()
	}

	accountExternalID := payload.Event.SubjectResource.AccountExternalID
	if accountExternalID == "" {
		return fmt.Errorf("account ID not found in the payload")
	}

	cloudAccountDetailsResponse, err := cloudAccountDetails(token, accountExternalID)
	if err != nil {
		return err
	}
	resourceID := cloudAccountDetailsResponse.CloudAccounts.Nodes[0].ID
	log.Printf("[%s] Resource ID for account ID %s is %s", requestID, accountExternalID, resourceID)

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.scanStatus[accountExternalID] {
		log.Printf("[%s] Checking if a scan/s is already in progress for resource ID %s", requestID, resourceID)
		sm.scanStatus[accountExternalID], _ = checkScanInProgress(token, resourceID)
	}

	if sm.scanStatus[accountExternalID] {
		log.Printf("[%s] Scan/s is already in progress for account ID: %s", requestID, accountExternalID)

		sm.scanQueue[accountExternalID] = append(sm.scanQueue[accountExternalID], ScanRequest{
			RequestID:      requestID,
			Payload:        payload,
			ResponseWriter: w,
		})

		log.Printf("[%s] Scan request queued for account ID: %s. Your request has been queued.", requestID, accountExternalID)
		log.Printf("[%s] Queue length for account ID: %s is %d", requestID, accountExternalID, len(sm.scanQueue[accountExternalID]))

		if !sm.monitorStarted[accountExternalID] {
			stopCh := make(chan struct{})
			sm.monitorStop[accountExternalID] = stopCh
			sm.monitorStarted[accountExternalID] = true
			go sm.monitorScanCompletion(accountExternalID, resourceID, stopCh)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Scan already in progress. Your request has been queued."})
		return nil
	}

	log.Printf("[%s] Calling Wiz API RequestResourceScan for resource ID: %s", requestID, resourceID)
	resourceScanResponse, err := wiz.RequestResourceScan(token, apiConfig.APIURL, resourceID)
	if err != nil {
		return err
	}

	responseBody, ok := resourceScanResponse.(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected response format")
	}

	log.Printf("[%s] Successfully started scan for resource ID: %s", requestID, resourceID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responseBody)

	return nil
}

func (sm *ScanManager) monitorScanCompletion(accountExternalID, resourceID string, stopCh <-chan struct{}) {
	log.Printf("Monitoring scan completion for account ID: %s, resource ID: %s", accountExternalID, resourceID)
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			log.Printf("Stopping monitor for account ID: %s", accountExternalID)
			return
		case <-ticker.C:
			tokenManager.mu.Lock()
			token := tokenManager.token
			tokenManager.mu.Unlock()

			log.Printf("Checking scan status for account ID: %s, resource ID: %s", accountExternalID, resourceID)
			checkScanInProgressResponse, err := checkScanInProgress(token, resourceID)
			if err != nil {
				log.Printf("Error while checking scan status: %v", err)
			}

			if !checkScanInProgressResponse {
				log.Printf("Scan/s completed for account ID: %s, resource ID: %s", accountExternalID, resourceID)

				sm.mu.Lock()
				delete(sm.scanStatus, accountExternalID)
				queuedRequests := sm.scanQueue[accountExternalID]
				delete(sm.scanQueue, accountExternalID)
				sm.mu.Unlock()

				if queuedRequests != nil {
					log.Printf("Processing queued scan requests for account ID: %s, resource ID: %s", accountExternalID, resourceID)
					_, err := wiz.RequestResourceScan(token, apiConfig.APIURL, resourceID)
					if err != nil {
						return
					}
				}

				sm.mu.Lock()
				delete(sm.monitorStarted, accountExternalID)
				delete(sm.monitorStop, accountExternalID)
				sm.mu.Unlock()

				return
			}
			log.Printf("Scan/s still in progress for account ID: %s, resource ID: %s", accountExternalID, resourceID)
		}
	}
}

func checkScanInProgress(token, resourceID string) (bool, error) {
	SystemActivityResponse, err := systemActivityStatus(token, resourceID)
	if err != nil {
		log.Printf("Error while checking scan status: %v", err)
		return false, err
	}

	if SystemActivityResponse.SystemActivities.TotalCount == 0 {
		return false, nil
	}

	return true, nil
}

func cloudAccountDetails(token, accountExternalID string) (models.CloudAccountsResponse, error) {
	cloudAccountsResponse, err := wiz.CloudAccounts(token, apiConfig.APIURL, accountExternalID)
	if err != nil {
		return models.CloudAccountsResponse{}, err
	}

	return cloudAccountsResponse, nil
}

func systemActivityStatus(token, resourceID string) (models.SystemActivityResponse, error) {
	systemActivityResponse, err := wiz.SystemActivityLogTable(token, apiConfig.APIURL, resourceID)
	if err != nil {
		return models.SystemActivityResponse{}, err
	}

	return systemActivityResponse, nil
}

func logRequestDetails(requestID string, payload models.WebhookPayload) {
	triggerRuleName := payload.Trigger.RuleName
	triggerSource := payload.Trigger.Source
	triggerType := payload.Trigger.Type
	eventName := payload.Event.Name
	eventResourceName := payload.Event.SubjectResource.Name

	log.Printf("[%s] Received: TriggerRuleName: %s, TriggerSource: %s, TriggerType: %s, EventName: %s, EventResourceName: %s",
		requestID, triggerRuleName, triggerSource, triggerType, eventName, eventResourceName)
}
