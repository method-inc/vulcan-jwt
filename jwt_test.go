package jwt

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/mailgun/vulcand/Godeps/_workspace/src/gopkg.in/check.v1"
	"github.com/vulcand/vulcand/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/vulcand/vulcand/Godeps/_workspace/src/github.com/vulcand/oxy/testutils"
	"github.com/vulcand/vulcand/plugin"
)

func init() {
	privateKeyData, _ := ioutil.ReadFile("jwt_test.rsa")
	privateKey, _ = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
	publicKeyData, _ := ioutil.ReadFile("jwt_test.rsa.pub")
	publicKey, _ = jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
}
func TestCL(t *testing.T) { TestingT(t) }

type JwtSuite struct {
}

var _ = Suite(&JwtSuite{})

// One of the most important tests:
// Make sure the JWT spec is compatible and will be accepted by middleware registry
func (s *JwtSuite) TestSpecIsOK(c *C) {
	c.Assert(plugin.NewRegistry().AddSpec(GetSpec()), IsNil)
}

func (s *JwtSuite) TestNew(c *C) {
	cl, err := New(publicKey)
	c.Assert(cl, NotNil)
	c.Assert(err, IsNil)

	c.Assert(cl.String(), Not(Equals), "")

	out, err := cl.NewHandler(nil)
	c.Assert(out, NotNil)
	c.Assert(err, IsNil)
}

func (s *JwtSuite) TestFromOther(c *C) {
	a, err := New(publicKey)
	c.Assert(a, NotNil)
	c.Assert(err, IsNil)

	out, err := FromOther(*a)
	c.Assert(err, IsNil)
	c.Assert(out, DeepEquals, a)
}

func (s *JwtSuite) TestAuthFromCli(c *C) {
	app := cli.NewApp()
	app.Name = "test"
	executed := false
	app.Action = func(ctx *cli.Context) {
		executed = true
		out, err := FromCli(ctx)
		c.Assert(out, NotNil)
		c.Assert(err, IsNil)
	}
	app.Flags = CliFlags()
	app.Run([]string{"test", "--publicKeyFile=jwt_test.rsa.pub"})
	c.Assert(executed, Equals, true)
}

func (s *JwtSuite) TestRequestSuccess(c *C) {
	token := CreateJWTToken("123")
	a := &JwtMiddleware{PublicKey: publicKey}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var claims map[string]interface{}
		json.Unmarshal([]byte(r.Header.Get(UserHeader)), &claims)

		c.Assert(claims["userid"], Equals, "123")
		io.WriteString(w, "treasure")
	})

	auth, err := a.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(auth)
	defer srv.Close()

	_, body, err := testutils.Get(srv.URL, testutils.Header("Authorization", "Bearer "+token))
	c.Assert(err, IsNil)
	c.Assert(string(body), Equals, "treasure")
}

func (s *JwtSuite) TestIgnoreOptions(c *C) {
	a := &JwtMiddleware{PublicKey: publicKey}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "treasure")
	})

	auth, err := a.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(auth)
	defer srv.Close()

	// bad token
	re, _, err := testutils.MakeRequest(srv.URL, testutils.Method("OPTIONS"))
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusOK)
}

func (s *JwtSuite) TestRequestBadToken(c *C) {
	a := &JwtMiddleware{PublicKey: publicKey}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "treasure")
	})

	auth, err := a.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(auth)
	defer srv.Close()

	// bad token
	re, _, err := testutils.Get(srv.URL, testutils.Header("Authorization", "open please"))
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusForbidden)

	// missing header
	re, _, err = testutils.Get(srv.URL)
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusForbidden)

	// malformed header
	re, _, err = testutils.Get(srv.URL, testutils.Header("Authorization", "blablabla="))
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusForbidden)
}

func (s *JwtSuite) TestRequestExpiredToken(c *C) {
	token := CreateExpiredJWTToken("123")
	a := &JwtMiddleware{PublicKey: publicKey}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "treasure")
	})

	auth, err := a.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(auth)
	defer srv.Close()

	re, body, err := testutils.Get(srv.URL, testutils.Header("Authorization", "Bearer "+*token))
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusForbidden)
	c.Assert(re.Header.Get("Content-Type"), Equals, "application/json")
	c.Assert(string(body), Equals, "{\"error\": \"forbidden\"}")

}

func CreateExpiredJWTToken(userId string) *string {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	claims := token.Claims.(jwt.MapClaims)

	claims["userid"] = userId
	claims["exp"] = time.Now().Unix() - 3600

	tokenString, _ := token.SignedString(privateKey)
	return &tokenString
}
