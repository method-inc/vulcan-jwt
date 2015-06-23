package jwt

import (
	jwt "github.com/dgrijalva/jwt-go"
	"time"
)

var (
	privateKey []byte
	publicKey  []byte
	keyfunc    jwt.Keyfunc
)

// CreateJWTToken is a helper method that provides
// a token string for the provided `userID`
// This sets the expiration date to 24 hours
func CreateJWTToken(userID string) *string {
	token := jwt.New(jwt.GetSigningMethod("RS256"))

	token.Claims["userid"] = userID
	token.Claims["exp"] = time.Now().Unix() + 3600

	tokenString, _ := token.SignedString(privateKey)
	return &tokenString
}
