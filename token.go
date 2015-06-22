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

func CreateJWTToken(userId string) *string {
	token := jwt.New(jwt.GetSigningMethod("RS256"))

	token.Claims["userid"] = userId
	token.Claims["exp"] = time.Now().Unix() + 3600

	tokenString, _ := token.SignedString(privateKey)
	return &tokenString
}
