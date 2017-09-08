package auth

import (
	"encoding/json"
	"net/http"

	"github.com/apprenda-kismatic/kubernetes-ldap/token"
	"github.com/golang/glog"
)

// TokenWebhook responds to requests from the K8s authentication webhook
type TokenWebhook struct {
	tokenVerifier token.Verifier
	ldapOU        string
}

// NewTokenWebhook returns a TokenWebhook with the given verifier
func NewTokenWebhook(verifier token.Verifier, ldapOU string) *TokenWebhook {
	return &TokenWebhook{
		tokenVerifier: verifier,
		ldapOU:        ldapOU,
	}
}

// ServeHTTP verifies the incoming token and sends the user's info
// back if the token is valid.
func (tw *TokenWebhook) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		resp.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	trr := &TokenReviewRequest{}
	err := json.NewDecoder(req.Body).Decode(trr)
	if err != nil {
		glog.Errorf("Error unmarshalling request: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer req.Body.Close()

	// Verify token
	token, err := tw.tokenVerifier.Verify(trr.Spec.Token)
	if err != nil {
		glog.Errorf("Token is invalid: %v", err)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Token is valid.
	userInfo := UserInfo{
		Username: token.Username,
	}
	if tw.ldapOU != "" {
		userInfo.Groups = []string{tw.ldapOU}
	}
	trr.Status = TokenReviewStatus{
		Authenticated: true,
		User: userInfo,
	}

	respJSON, err := json.Marshal(trr)
	if err != nil {
		glog.Errorf("Error marshalling response: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp.Header().Add("Content-Type", "application/json")
	resp.Write(respJSON)
}
