package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kismatic/kubernetes-ldap/token/proto"
)

type dummyVerifier struct {
	token *pb.Token
	err   error
}

func (dv *dummyVerifier) Verify(s string) (token *pb.Token, err error) {
	return dv.token, dv.err
}

func TestWebhook(t *testing.T) {

	cases := []struct {
		reqMethod     string
		verifiedToken *pb.Token
		verifyErr     error
		authenticated bool
		expectedCode  int
	}{
		{
			// Happy path. Token is valid
			reqMethod: "POST",
			verifiedToken: &pb.Token{
				Username: "username",
			},
			authenticated: true,
			expectedCode:  http.StatusOK,
		},
		{
			// The token provided by user is invalid
			reqMethod:     "POST",
			verifyErr:     errors.New("Invalid token provided"),
			authenticated: false,
			expectedCode:  http.StatusUnauthorized,
		},
		{
			// Incorrect method used on endpoint
			reqMethod:    "GET",
			expectedCode: http.StatusMethodNotAllowed,
		},
	}

	for i, c := range cases {
		v := &dummyVerifier{token: c.verifiedToken, err: c.verifyErr}
		tw := NewTokenWebhook(v)

		trr := &TokenReviewRequest{
			Spec: TokenReviewSpec{
				Token: "someToken",
			},
		}
		trrJSON, err := json.Marshal(trr)
		if err != nil {
			t.Errorf("Case: %d: Error marshaling TokenReviewRequest: %v", i, err)
		}

		req, err := http.NewRequest(c.reqMethod, "", bytes.NewReader(trrJSON))
		if err != nil {
			t.Errorf("Case: %d: Error creating request: %v", i, err)
		}

		rec := httptest.NewRecorder()
		tw.ServeHTTP(rec, req)

		if rec.Code != c.expectedCode {
			t.Errorf("Case: %d: Expected '%d' from server. Got '%d", i, c.expectedCode, rec.Code)
		}

		// Assertions for the 200 status case
		if rec.Code == http.StatusOK {
			err = json.NewDecoder(rec.Body).Decode(trr)
			if err != nil {
				t.Errorf("Case: %d: Error decoding response: %v", i, err)
			}

			if trr.Status.Authenticated != c.authenticated {
				t.Errorf("Case: %d: Unexpected authenticated status. Expected: %t. Got: %t", i, c.authenticated, trr.Status.Authenticated)
			}

			if trr.Status.Authenticated && trr.Status.User.Username != c.verifiedToken.Username {
				t.Errorf("Case: %d: Expected username: %s. Got %s", i, c.verifiedToken.Username, trr.Status.User)
			}
		}
	}
}
