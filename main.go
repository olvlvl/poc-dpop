package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Security Constants
const (
	DPoPMaxAge        = 5 * time.Minute
	ReplayWindow      = 6 * time.Minute
	AccessTokenMaxAge = 1 * time.Hour
	NonceLength       = 32
)

// NoncePolicy defines the nonce validation policy for DPoP validation
type NoncePolicy bool

const (
	NonceRequired          NoncePolicy = true  // Nonce must be present and valid
	NonceValidateIfPresent NoncePolicy = false // Nonce is validated if present, but not required
)

const (
	DPoPErrorInvalidProof = "invalid_dpop_proof"
	DPoPErrorUseDPoPNonce = "use_dpop_nonce"
)

var ErrNonceRequired = errors.New("dpop nonce required or invalid")

// IsBehindTrustedProxy marks whether the server expects to be behind a trusted proxy.
// When true, X-Forwarded-Proto headers are trusted for scheme detection.
// TODO: In production, this should be read from environment variables.
var IsBehindTrustedProxy = true

//
// JTI Store for Replay Attack Prevention
//

// JTIStore manages used JTI values to prevent replay attacks
type JTIStore struct {
	store map[string]time.Time
	mu    sync.RWMutex
}

func NewJTIStore() *JTIStore {
	return &JTIStore{
		store: make(map[string]time.Time),
	}
}

// IsUsed checks if a JTI has been used and marks it if not
func (js *JTIStore) IsUsed(jti string) bool {
	js.mu.Lock()
	defer js.mu.Unlock()

	// Clean up expired JTIs
	now := time.Now()
	for key, expiry := range js.store {
		if now.After(expiry) {
			delete(js.store, key)
		}
	}

	// Check replay
	expiry, found := js.store[jti]
	return found && now.Before(expiry)
}

// MarkUsed marks a JTI as used until the provided expiry
func (js *JTIStore) MarkUsed(jti string, expiry time.Time) {
	js.mu.Lock()
	defer js.mu.Unlock()

	js.store[jti] = expiry
}

// CleanupExpired removes expired JTIs (can be called periodically)
func (js *JTIStore) CleanupExpired() {
	js.mu.Lock()
	defer js.mu.Unlock()

	now := time.Now()
	for key, expiry := range js.store {
		if now.After(expiry) {
			delete(js.store, key)
		}
	}
}

//
// Nonce Store for Challenge-Response
//

// NonceStore manages server-issued nonces
type NonceStore struct {
	nonces map[string]time.Time
	mu     sync.RWMutex
}

func NewNonceStore() *NonceStore {
	return &NonceStore{
		nonces: make(map[string]time.Time),
	}
}

// Issue creates a new nonce and stores it
func (ns *NonceStore) Issue() string {
	nonce := generateNonce()

	ns.mu.Lock()
	defer ns.mu.Unlock()

	ns.nonces[nonce] = time.Now().Add(ReplayWindow)
	return nonce
}

// Validate checks if a nonce is valid and removes it (single-use)
func (ns *NonceStore) Validate(nonce string) bool {
	if nonce == "" {
		return false // empty nonce is not valid here — caller decides whether empty is acceptable
	}

	ns.mu.Lock()
	defer ns.mu.Unlock()

	expiry, found := ns.nonces[nonce]
	if !found {
		return false
	}

	// Check if expired
	if time.Now().After(expiry) {
		delete(ns.nonces, nonce)
		return false
	}

	// Single-use: remove after validation
	delete(ns.nonces, nonce)
	return true
}

// CleanupExpired removes expired nonces
func (ns *NonceStore) CleanupExpired() {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	now := time.Now()
	for key, expiry := range ns.nonces {
		if now.After(expiry) {
			delete(ns.nonces, key)
		}
	}
}

//
// Global stores (in production, use Redis or similar)
//

var (
	jtiStore   *JTIStore
	nonceStore *NonceStore
)

//
// Helper Functions
//

// base64URLEncode encodes raw bytes to Base64URL without padding
func base64URLEncode(input []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(input), "=")
}

// hashAndEncode hashes data using SHA-256 and Base64URL-encodes the result
func hashAndEncode(data []byte) string {
	h := sha256.Sum256(data)
	return base64URLEncode(h[:])
}

// getFullURL reconstructs the full URL including scheme and host,
// prioritizing the secure scheme determination.
func getFullURL(r *http.Request) string {
	scheme := "http"

	// Check the actual TLS connection first (most reliable)
	if r.TLS != nil {
		scheme = "https"
	} else if IsBehindTrustedProxy {
		// Only trust proxy headers if explicitly configured
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = strings.ToLower(proto)
		}
	}

	return fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)
}

// parseECPublicKeyFromJWK reconstructs an *ecdsa.PublicKey from a JWK
func parseECPublicKeyFromJWK(jwkMap map[string]interface{}) (*ecdsa.PublicKey, error) {
	// Validate key type and curve
	kty, ok := jwkMap["kty"].(string)
	if !ok || kty != "EC" {
		return nil, fmt.Errorf("jwk 'kty' must be 'EC'")
	}
	crv, ok := jwkMap["crv"].(string)
	if !ok || crv != "P-256" {
		return nil, fmt.Errorf("jwk 'crv' must be 'P-256'")
	}

	// Get and decode x and y coordinates
	xStr, ok := jwkMap["x"].(string)
	if !ok {
		return nil, fmt.Errorf("jwk missing 'x' coordinate")
	}
	yStr, ok := jwkMap["y"].(string)
	if !ok {
		return nil, fmt.Errorf("jwk missing 'y' coordinate")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'x' coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'y' coordinate: %w", err)
	}

	// Convert to *big.Int and construct public key
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return publicKey, nil
}

// computeJWKThumbprint produces an RFC-7638-compliant JWK thumbprint (JKT) for an EC P-256 key
func computeJWKThumbprint(jwkMap map[string]interface{}) (string, error) {
	// Build a deterministic map[string]string with the required members
	m := map[string]string{
		"crv": "",
		"kty": "",
		"x":   "",
		"y":   "",
	}

	if v, ok := jwkMap["crv"].(string); ok {
		m["crv"] = v
	} else {
		return "", fmt.Errorf("jwk missing 'crv'")
	}
	if v, ok := jwkMap["kty"].(string); ok {
		m["kty"] = v
	} else {
		return "", fmt.Errorf("jwk missing 'kty'")
	}
	if v, ok := jwkMap["x"].(string); ok {
		m["x"] = v
	} else {
		return "", fmt.Errorf("jwk missing 'x'")
	}
	if v, ok := jwkMap["y"].(string); ok {
		m["y"] = v
	} else {
		return "", fmt.Errorf("jwk missing 'y'")
	}

	// json.Marshal on a map will produce deterministic output with sorted keys
	buf, err := json.Marshal(m)
	if err != nil {
		return "", err
	}

	return hashAndEncode(buf), nil
}

//
// DPoP Claims and Structures
//

// DPoPClaims represents the DPoP JWT claims
type DPoPClaims struct {
	jwt.RegisteredClaims
	Htm   string `json:"htm"`
	Htu   string `json:"htu"`
	Ath   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// AccessTokenClaims represents the access token's payload
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Cnf struct {
		Jkt string `json:"jkt"`
	} `json:"cnf"`
	Scope string `json:"scope,omitempty"`
}

//
// DPoP Validation
//

// validateDPoPProof performs server-side DPoP validation
func validateDPoPProof(r *http.Request, noncePolicy NoncePolicy) (string, error) {
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return "", fmt.Errorf("DPoP header is missing")
	}

	parser := jwt.NewParser(jwt.WithJSONNumber(), jwt.WithLeeway(5*time.Second))
	var jkt string

	token, err := parser.ParseWithClaims(dpopHeader, &DPoPClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Get JWK from header
		jwkInterface, ok := token.Header["jwk"]
		if !ok {
			return nil, fmt.Errorf("DPoP JWT header missing 'jwk'")
		}
		jwkMap, ok := jwkInterface.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("DPoP JWT header 'jwk' is not a valid JSON object")
		}

		// Check 'typ' and 'alg'
		if token.Header["typ"] != "dpop+jwt" {
			return nil, fmt.Errorf("DPoP JWT 'typ' must be 'dpop+jwt'")
		}
		if token.Header["alg"] != "ES256" {
			return nil, fmt.Errorf("DPoP JWT 'alg' must be 'ES256'")
		}

		// Validate JWK thumbprint (jkt) using RFC-7638 canonicalization
		var err error
		jkt, err = computeJWKThumbprint(jwkMap)
		if err != nil {
			return nil, fmt.Errorf("failed to compute jkt: %w", err)
		}

		// Parse public key for verification
		return parseECPublicKeyFromJWK(jwkMap)
	})

	if err != nil {
		return "", fmt.Errorf("DPoP JWT validation failed: %w", err)
	}

	claims, ok := token.Claims.(*DPoPClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("DPoP JWT is invalid")
	}

	// Validate JTI
	if claims.ID == "" {
		return "", fmt.Errorf("DPoP JWT missing 'jti' claim")
	}
	// Calculate expiry for this JTI based on iat + DPoPMaxAge
	if claims.IssuedAt == nil {
		return "", fmt.Errorf("DPoP JWT missing 'iat' claim")
	}

	if jtiStore.IsUsed(claims.ID) {
		return "", fmt.Errorf("DPoP JWT 'jti' has been used")
	}
	// Mark as used with deterministic expiry
	jtiStore.MarkUsed(claims.ID, claims.IssuedAt.Time.Add(DPoPMaxAge))

	// Validate IAT
	age := time.Since(claims.IssuedAt.Time)
	if age > DPoPMaxAge {
		return "", fmt.Errorf("DPoP JWT 'iat' is too old")
	}
	if age < -time.Minute {
		return "", fmt.Errorf("DPoP JWT 'iat' is in the future")
	}

	// Validate nonce if required
	if noncePolicy == NonceRequired {
		if !nonceStore.Validate(claims.Nonce) {
			return "", ErrNonceRequired
		}
	} else if claims.Nonce != "" {
		// validate if present
		if !nonceStore.Validate(claims.Nonce) {
			return "", ErrNonceRequired
		}
	}

	// Validate HTM (case-insensitive)
	if !strings.EqualFold(claims.Htm, r.Method) {
		return "", fmt.Errorf("DPoP JWT 'htm' claim mismatch")
	}

	// Validate HTU
	fullRequestURL := getFullURL(r)
	normalizedURL, err := normalizeHtu(fullRequestURL)
	if err != nil {
		return "", fmt.Errorf("failed to normalize request URL: %w", err)
	}
	if claims.Htu != normalizedURL {
		return "", fmt.Errorf("DPoP JWT 'htu' claim mismatch")
	}

	return jkt, nil
}

// normalizeHtu normalizes the HTTP URL for DPoP validation
func normalizeHtu(rawURL string) (string, error) {
	// The server must apply the same normalization logic as the client.
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	scheme := strings.ToLower(parsedURL.Scheme)
	host := strings.ToLower(parsedURL.Hostname())
	port := parsedURL.Port()

	// Remove default ports
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}

	portPart := ""
	if port != "" {
		portPart = fmt.Sprintf(":%s", port)
	}

	// Use EscapedPath() to preserve percent-encoding details the client may use
	path := parsedURL.EscapedPath()
	if path == "" {
		path = "/"
	}

	// Include only scheme, host, port, and path (no query or fragment)
	return fmt.Sprintf("%s://%s%s%s", scheme, host, portPart, path), nil
}

// generateNonce creates a cryptographically secure random nonce
func generateNonce() string {
	nonceBytes := make([]byte, NonceLength)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		log.Printf("Failed to generate random nonce: %v", err)
		// Fallback (less secure)
		return hashAndEncode([]byte(time.Now().String()))
	}
	return base64.RawURLEncoding.EncodeToString(nonceBytes)
}

// dpopChallenge sends a DPoP challenge with a fresh nonce
func dpopChallenge(w http.ResponseWriter, errorType string, reason string) {
	log.Printf("DPoP Challenge issued: %s", reason)
	newNonce := nonceStore.Issue()
	// Include the nonce in the WWW-Authenticate header as per modern practice and RFC guidance
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`DPoP realm="dpop", error="%s", dpop_nonce="%s"`, errorType, newNonce))
	// Provide a convenience header as well
	w.Header().Set("DPoP-Nonce", newNonce)
	http.Error(w, reason, http.StatusUnauthorized)
}

//
// Token Generation
//

var (
	RSAPrivateKey *rsa.PrivateKey
	RSAPublicKey  *rsa.PublicKey
)

// generateAccessToken creates a JWT bound to the provided JKT
func generateAccessToken(jkt, subject string) (string, error) {
	now := time.Now()
	expirationTime := now.Add(AccessTokenMaxAge)

	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "dpop-auth-server",
			Subject:   subject,
			Audience:  []string{"dpop-resource-server"},
		},
		Scope: "read write",
	}

	// Bind the JKT to the token
	claims.Cnf.Jkt = jkt

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(RSAPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return tokenString, nil
}

// extractJktFromAccessToken validates the access token and returns the bound JKT
func extractJktFromAccessToken(authHeader string) (string, error) {
	if !strings.HasPrefix(authHeader, "DPoP ") {
		return "", errors.New("authorization header must use DPoP scheme")
	}
	accessToken := strings.TrimPrefix(authHeader, "DPoP ")

	claims := &AccessTokenClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return RSAPublicKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("access token validation failed: %w", err)
	}

	if !token.Valid {
		return "", errors.New("access token is invalid")
	}

	// Check token expiration explicitly
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		return "", errors.New("access token has expired")
	}

	// Check JKT binding exists
	if claims.Cnf.Jkt == "" {
		return "", errors.New("access token missing JKT binding")
	}

	return claims.Cnf.Jkt, nil
}

//
// HTTP Handlers
//

// handleTokenRequest handles token issuance.
// DPoP Flow: Client presents a DPoP proof without a nonce on first request.
// Server validates the proof and issues both an access token and a fresh nonce.
// The client must use this nonce for subsequent resource requests.
func handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate DPoP proof (nonce not required for initial token request)
	jkt, err := validateDPoPProof(r, NonceValidateIfPresent)
	if err != nil {
		log.Printf("DPoP validation failed: %v", err)
		dpopChallenge(w, DPoPErrorInvalidProof, "Invalid or missing DPoP proof")
		return
	}

	// Parse request body
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
		return
	}

	// Generate access token bound to JKT
	accessToken, err := generateAccessToken(jkt, "client-123")
	if err != nil {
		log.Printf("Token generation failed: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "DPoP",
		"expires_in":   int(AccessTokenMaxAge.Seconds()),
	}

	// Send Response
	w.Header().Set("Content-Type", "application/json")
	// Issue fresh nonce for subsequent resource requests
	w.Header().Set("DPoP-Nonce", nonceStore.Issue())
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleResourceRequest handles resource access
func handleResourceRequest(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Access Granted: resource delivered successfully."))
}

//
// Middleware
//

// enableCORS adds CORS headers
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// In production, specify exact origins instead of "*"
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP")
		w.Header().Set("Access-Control-Expose-Headers", "DPoP-Nonce")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// dpopValidator enforces DPoP proof-of-possession for protected resources.
// This middleware validates that:
// 1. Both Authorization and DPoP headers are present
// 2. The access token is valid and contains a JKT binding
// 3. The DPoP proof is valid and includes the required nonce
// 4. The JKT from the proof matches the JKT bound to the access token
func dpopValidator(next http.HandlerFunc, noncePolicy NoncePolicy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		dpopProof := r.Header.Get("DPoP")

		if authHeader == "" || dpopProof == "" {
			// Issue challenge to guide the client on what's needed
			reason := "Missing DPoP authentication"
			if authHeader == "" {
				reason = "Missing Authorization header"
			} else if dpopProof == "" {
				reason = "Missing DPoP proof header"
			}
			dpopChallenge(w, DPoPErrorInvalidProof, reason)
			return
		}

		// Validate access token and extract expected JKT
		expectedJkt, err := extractJktFromAccessToken(authHeader)
		if err != nil {
			log.Printf("Access token validation failed: %v", err)
			http.Error(w, "Invalid access token", http.StatusUnauthorized)
			return
		}

		// Validate DPoP proof (nonce may be required)
		proofJkt, err := validateDPoPProof(r, noncePolicy)
		if err != nil {
			log.Printf("DPoP proof validation failed: %v", err)

			errorType := DPoPErrorInvalidProof
			reason := "Invalid DPoP proof"

			if errors.Is(err, ErrNonceRequired) {
				errorType = DPoPErrorUseDPoPNonce
				reason = "Missing or expired DPoP nonce"
			}

			dpopChallenge(w, errorType, reason)
			return
		}

		// Enforce token binding - the proof must be from the same key as the token
		// Use constant-time comparison to avoid timing leakage
		if subtle.ConstantTimeCompare([]byte(proofJkt), []byte(expectedJkt)) != 1 {
			log.Printf("Token binding validation failed")
			http.Error(w, "Token binding mismatch", http.StatusForbidden)
			return
		}

		// We issue fresh nonce on successful validation, so the next request is not challenged.
		w.Header().Set("DPoP-Nonce", nonceStore.Issue())

		next.ServeHTTP(w, r)
	}
}

//
// Initialization and Cleanup
//

// initKeys generates RSA key pair for signing access tokens.
// In production, keys should be loaded from secure storage (KMS, files, etc.)
// and rotated periodically.
func initKeys() {
	log.Println("Generating RSA 2048-bit key pair...")
	var err error
	RSAPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA private key: %v", err)
	}
	RSAPublicKey = &RSAPrivateKey.PublicKey
	log.Println("RSA key pair generated successfully.")
}

// initConfig loads configuration from environment variables.
// This should be called before starting the server.
func initConfig() {
	// Example: Load IsBehindTrustedProxy from environment
	// if os.Getenv("BEHIND_TRUSTED_PROXY") == "true" {
	//     IsBehindTrustedProxy = true
	// }

	log.Printf("Configuration: IsBehindTrustedProxy=%v", IsBehindTrustedProxy)
}

// startCleanupRoutines starts background cleanup goroutines
func startCleanupRoutines() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			jtiStore.CleanupExpired()
			nonceStore.CleanupExpired()
		}
	}()
}

//
// Main
//

func main() {
	log.Println("=== DPoP Server Initialization ===")

	// Load configuration
	initConfig()

	// Initialize stores
	jtiStore = NewJTIStore()
	nonceStore = NewNonceStore()
	log.Println("JTI and Nonce stores initialized")

	// Initialize cryptographic keys
	initKeys()

	// Start cleanup routines
	startCleanupRoutines()
	log.Println("Background cleanup routines started")

	// Define endpoints
	http.HandleFunc("/token", enableCORS(handleTokenRequest))
	http.HandleFunc("/high-value-resource", enableCORS(dpopValidator(handleResourceRequest, NonceRequired)))
	http.HandleFunc("/low-value-resource", enableCORS(dpopValidator(handleResourceRequest, NonceValidateIfPresent)))
	http.HandleFunc("/challenge", enableCORS(dpopValidator(handleResourceRequest, NonceRequired)))

	port := ":8080"
	log.Println("=== Server Configuration ===")
	log.Printf("Listening on: %s", port)
	log.Printf("Token endpoint: http://localhost%s/token", port)
	log.Printf("High value endpoint: http://localhost%s/high-value-resource", port)
	log.Printf("Low value endpoint: http://localhost%s/low-value-resource", port)
	log.Println("=================================")
	log.Println("⚠️  WARNING: Using HTTP for local testing only!")
	log.Println("⚠️  PRODUCTION DEPLOYMENT REQUIRES HTTPS!")
	log.Println("=================================")

	// Start server
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}
