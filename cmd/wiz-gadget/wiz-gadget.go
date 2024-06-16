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
	username        string
	password        string
	token           string
	clientID        string
	clientSecret    string
	authURL         string
	apiURL          string
	ipWhitelist     []string
	apiToken        string
	tokenMutex      sync.Mutex
	tokenExpires    time.Time
	scanQueue       = make(map[string][]ScanRequest)
	scanQueueMutex  sync.Mutex
	scanStatus      = make(map[string]bool)
	scanStatusMutex sync.Mutex
	monitorStarted  map[string]bool          = make(map[string]bool)
	monitorStop     map[string]chan struct{} = make(map[string]chan struct{})
	monitorMutex    sync.Mutex
)

type ScanRequest struct {
	RequestID      string
	Payload        models.WebhookPayload
	ResponseWriter http.ResponseWriter
}

func init() {
	log.Println("Starting Wiz Gadget Server")

	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(); err != nil {
			log.Fatalf("Error loading .env file: %v", err)
		}
		log.Println(".env file loaded successfully")
	}

	username = os.Getenv("BASIC_AUTH_USERNAME")
	password = os.Getenv("BASIC_AUTH_PASSWORD")
	token = os.Getenv("TOKEN_AUTH")
	clientID = os.Getenv("OAUTH_CLIENT_ID")
	clientSecret = os.Getenv("OAUTH_CLIENT_SECRET")
	authURL = os.Getenv("OAUTH_AUTH_URL")
	apiURL = os.Getenv("API_URL")

	ipWhitelistEnv := os.Getenv("IP_WHITELIST")
	if ipWhitelistEnv != "" {
		ipWhitelist = strings.Split(ipWhitelistEnv, ",")
	} else {
		log.Fatal("IP_WHITELIST environment variable is not set")
	}
}

type OAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func main() {
	if err := getOAuthToken(); err != nil {
		log.Fatalf("Failed to obtain Wiz OAuth token: %v", err)
	}

	http.HandleFunc("/webhook", WebhookHandler)

	server := &http.Server{
		Addr: ":8181",
	}

	if _, err := os.Stat(crtFile); os.IsNotExist(err) {
		log.Fatalf("Certificate file %s not found, stopping application", crtFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Fatalf("Key file %s not found, stopping application", keyFile)
	}

	log.Printf("Wiz Gadget now listening on port %s", server.Addr)
	if err := server.ListenAndServeTLS(crtFile, keyFile); err != nil {
		log.Fatalf("Failed to start HTTPS server: %v", err)
	}
}

func WebhookHandler(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()
	ip := getIPAddress(r)

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

	if err := handleScanRequest(requestID, payload, w); err != nil {
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
	for _, whitelistedIP := range ipWhitelist {
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
		return len(creds) == 2 && creds[0] == username && creds[1] == password
	}

	if strings.HasPrefix(auth, bearerPrefix) {
		return auth[len(bearerPrefix):] == token
	}

	return false
}

func isValidPayload(payload models.WebhookPayload) bool {
	return payload.Event.SubjectResource.AccountExternalID != ""
}

func getOAuthToken() error {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("audience", "wiz-api")

	req, err := http.NewRequest("POST", authURL, strings.NewReader(data.Encode()))
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

	tokenMutex.Lock()
	apiToken = tokenResp.AccessToken
	tokenExpires = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	tokenMutex.Unlock()

	return nil
}

func handleScanRequest(requestID string, payload models.WebhookPayload, w http.ResponseWriter) error {
	tokenMutex.Lock()
	token := apiToken
	expires := tokenExpires
	tokenMutex.Unlock()

	// Refresh the token if it's about to expire
	if time.Until(expires) < 1*time.Minute {
		if err := getOAuthToken(); err != nil {
			return err
		}
		tokenMutex.Lock()
		token = apiToken
		tokenMutex.Unlock()
	}

	// Extract account ID from the payload
	accountExternalID := payload.Event.SubjectResource.AccountExternalID
	if accountExternalID == "" {
		return fmt.Errorf("account ID not found in the payload")
	}

	// Get the resource ID for the account
	cloudAccountDetailsResponse, err := cloudAccountDetails(token, accountExternalID)
	if err != nil {
		return err
	}
	resourceID := cloudAccountDetailsResponse.CloudAccounts.Nodes[0].ID
	log.Printf("[%s] Resource ID for account ID %s is %s", requestID, accountExternalID, resourceID)

	// Check if a scan is already in progress for the account
	if !scanStatus[accountExternalID] {
		scanStatusMutex.Lock()
		log.Printf("[%s] Checking if a scan is already in progress for resource ID %s", requestID, resourceID)
		scanStatus[accountExternalID], _ = checkScanInProgress(token, resourceID)
		scanStatusMutex.Unlock()
	}

	// If a scan is in progress, queue the request
	scanStatusMutex.Lock()
	if scanStatus[accountExternalID] {
		log.Printf("[%s] Scan is already in progress for account ID: %s", requestID, accountExternalID)
		scanStatusMutex.Unlock()

		// Queue the request
		scanQueueMutex.Lock()
		scanQueue[accountExternalID] = append(scanQueue[accountExternalID], ScanRequest{
			RequestID:      requestID,
			Payload:        payload,
			ResponseWriter: w,
		})
		scanQueueMutex.Unlock()
		log.Printf("[%s] Scan request queued for account ID: %s. Your request has been queued.", requestID, accountExternalID)
		log.Printf("[%s] Queue length for account ID: %s is %d", requestID, accountExternalID, len(scanQueue[accountExternalID]))

		// Start monitoring if not already started
		monitorMutex.Lock()
		if !monitorStarted[accountExternalID] {
			// Start the monitor only once
			stopCh := make(chan struct{})
			monitorStop[accountExternalID] = stopCh
			monitorStarted[accountExternalID] = true
			go monitorScanCompletion(accountExternalID, resourceID, stopCh)
		}
		monitorMutex.Unlock()

		return nil
	}
	scanStatusMutex.Unlock()

	// Start the resource scan
	log.Printf("[%s] Calling Wiz API RequestResourceScan for resource ID: %s", requestID, resourceID)
	resourceScanResponse, err := wiz.RequestResourceScan(token, apiURL, resourceID)
	if err != nil {
		return err
	}

	// Return the response
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

func monitorScanCompletion(accountExternalID, resourceID string, stopCh <-chan struct{}) {
	log.Printf("Monitoring scan completion for account ID: %s, resource ID: %s", accountExternalID, resourceID)
	ticker := time.NewTicker(15 * time.Minute) // adjust interval as needed
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			log.Printf("Stopping monitor for account ID: %s", accountExternalID)
			return
		case <-ticker.C:
			tokenMutex.Lock()
			token := apiToken
			tokenMutex.Unlock()

			log.Printf("Checking scan status for account ID: %s, resource ID: %s", accountExternalID, resourceID)
			checkScanInProgressResponse, err := checkScanInProgress(token, resourceID)
			if err != nil {
				log.Printf("Error while checking scan status: %v", err)
			}

			if !checkScanInProgressResponse {
				log.Printf("Scan/s completed for account ID: %s, resource ID: %s", accountExternalID, resourceID)

				scanStatusMutex.Lock()
				delete(scanStatus, accountExternalID)
				scanStatusMutex.Unlock()

				scanQueueMutex.Lock()
				queuedRequests := scanQueue[accountExternalID]
				delete(scanQueue, accountExternalID)
				scanQueueMutex.Unlock()

				if queuedRequests != nil {
					log.Printf("Processing queued scan requests for account ID: %s, resource ID: %s", accountExternalID, resourceID)
					// handleScanRequest(queuedRequests[0].RequestID, queuedRequests[0].Payload, queuedRequests[0].ResponseWriter)

					// Start the resource scan
					log.Printf("[%s] Calling Wiz API RequestResourceScan for resource ID: %s", queuedRequests[0].RequestID, resourceID)
					_, err := wiz.RequestResourceScan(token, apiURL, resourceID)
					if err != nil {
						return
					}
				}

				monitorMutex.Lock()
				delete(monitorStarted, accountExternalID)
				delete(monitorStop, accountExternalID)
				monitorMutex.Unlock()

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
	cloudAccountsResponse, err := wiz.CloudAccounts(token, apiURL, accountExternalID)
	if err != nil {
		return models.CloudAccountsResponse{}, err
	}

	return cloudAccountsResponse, nil
}

func systemActivityStatus(token, resourceID string) (models.SystemActivityResponse, error) {
	systemActivityResponse, err := wiz.SystemActivityLogTable(token, apiURL, resourceID)
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
