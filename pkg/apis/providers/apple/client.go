package apple

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	tokenValidationURL        = "https://appleid.apple.com/auth/token"
	tokenRevokeURL            = "https://appleid.apple.com/auth/revoke"
	UserAgent          string = "oauth2-proxy"
	ContentType        string = "application/x-www-form-urlencoded"
	AcceptHeader       string = "application/json"
)

type Client struct {
	tokenValidationURL string
	tokenRevokeURL     string
	client             *http.Client
}

func NewClient() *Client {
	return &Client{
		tokenValidationURL: tokenValidationURL,
		tokenRevokeURL:     tokenRevokeURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (c *Client) VerifyToken(ctx context.Context, validationRequest TokenValidationRequest) (result interface{}, err error) {
	data := url.Values{}
	data.Set("client_id", validationRequest.ClientID)
	data.Set("client_secret", validationRequest.ClientSecret)
	data.Set("code", validationRequest.Code)
	data.Set("redirect_uri", validationRequest.RedirectURI)
	data.Set("grant_type", "authorization_code")

	return doRequest(ctx, c.client, c.tokenValidationURL, data)
}

func doRequest(ctx context.Context, client *http.Client, url string, data url.Values) (result interface{}, err error) {
	request, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(data.Encode()))
	if err != nil {
		return result, err
	}

	request.Header.Add("content-type", ContentType)
	request.Header.Add("accept", AcceptHeader)
	request.Header.Add("user-agent", UserAgent) // apple requires a user agent

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	err = json.NewDecoder(response.Body).Decode(result)
	if err != nil {
		return nil, err
	}
	return result, err
}
