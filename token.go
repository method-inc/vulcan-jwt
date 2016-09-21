package jwt

import (
	"crypto/rsa"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyfunc    jwt.Keyfunc
)

// CreateJWTToken is a helper method that provides
// a token string for the provided `userID`
// This sets the expiration date to 24 hours
func CreateJWTToken(userID string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"userid": userID,
		"exp":    time.Now().Unix() + 3600,
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}
	return tokenString
}
