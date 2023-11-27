package apple

type TokenValidationRequest struct {
	ClientID     string
	ClientSecret string
	Code         string
	RedirectURI  string
}
