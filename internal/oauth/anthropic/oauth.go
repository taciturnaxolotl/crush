// Package anthropic handles the Anthropic OAuth PKCE authorization code flow.
package anthropic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/crush/internal/oauth"
)

const (
	clientID     = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	authorizeURL = "https://claude.ai/oauth/authorize"
	tokenURL     = "https://platform.claude.com/v1/oauth/token"
	redirectURI  = "https://platform.claude.com/oauth/code/callback"
	apiKeyURL    = "https://api.anthropic.com/api/oauth/claude_cli/create_api_key"

	// Request all scopes; the backend grants what applies to the user's
	// account. After exchange, check HasInferenceScope to decide whether to
	// use the bearer token directly (Claude.ai Pro/Max) or create an API key
	// (Console / paid API).
	scope = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
)

// AuthParams contains the parameters needed to complete the OAuth flow.
type AuthParams struct {
	AuthURL      string
	CodeVerifier string
	State        string
}

// TokenResponse is the raw response from the token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// InitiateAuth generates PKCE parameters and builds the authorization URL.
// The user must open the URL, authorize, and paste back the code#state string.
func InitiateAuth() (*AuthParams, error) {
	verifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("generate code verifier: %w", err)
	}
	challenge := generateCodeChallenge(verifier)

	state, err := generateState()
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	params := url.Values{
		"code":                  {"true"}, // shows Claude Max upsell
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {scope},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	return &AuthParams{
		AuthURL:      authorizeURL + "?" + params.Encode(),
		CodeVerifier: verifier,
		State:        state,
	}, nil
}

// ExchangeCode exchanges the authorization code for tokens.
// code and state come from the user pasting the code#state string.
func ExchangeCode(ctx context.Context, code, codeVerifier, state string) (*oauth.Token, *TokenResponse, error) {
	body, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"state":         state,
		"client_id":     clientID,
		"redirect_uri":  redirectURI,
		"code_verifier": codeVerifier,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal request: %w", err)
	}

	var resp TokenResponse
	if err := postJSON(ctx, tokenURL, nil, body, &resp); err != nil {
		return nil, nil, fmt.Errorf("token exchange: %w", err)
	}

	token := &oauth.Token{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
	}
	token.SetExpiresAt()
	return token, &resp, nil
}

// RefreshToken uses a refresh token to obtain a new access token.
func RefreshToken(ctx context.Context, refreshToken string) (*oauth.Token, error) {
	body, err := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     clientID,
		"scope":         "user:inference user:profile",
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	var resp TokenResponse
	if err := postJSON(ctx, tokenURL, nil, body, &resp); err != nil {
		return nil, fmt.Errorf("token refresh: %w", err)
	}

	token := &oauth.Token{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.ExpiresIn,
	}
	token.SetExpiresAt()
	return token, nil
}

// CreateAPIKey creates a permanent API key using an OAuth access token.
// Used for Console users who don't have the user:inference scope.
func CreateAPIKey(ctx context.Context, accessToken string) (string, error) {
	var result struct {
		RawKey string `json:"raw_key"`
	}
	authHeader := map[string]string{"Authorization": "Bearer " + accessToken}
	if err := postJSON(ctx, apiKeyURL, authHeader, nil, &result); err != nil {
		return "", fmt.Errorf("create api key: %w", err)
	}
	if result.RawKey == "" {
		return "", fmt.Errorf("no api key returned")
	}
	return result.RawKey, nil
}

// HasInferenceScope reports whether the scope string grants direct inference
// access (Claude.ai Pro/Max subscribers). If true, the bearer token can be
// used directly; otherwise CreateAPIKey should be called.
func HasInferenceScope(scopeStr string) bool {
	for _, s := range strings.Fields(scopeStr) {
		if s == "user:inference" {
			return true
		}
	}
	return false
}

// postJSON sends a JSON POST and decodes the response into out.
func postJSON(ctx context.Context, endpoint string, headers map[string]string, body []byte, out any) error {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, respBody)
	}
	return json.Unmarshal(respBody, out)
}

func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
