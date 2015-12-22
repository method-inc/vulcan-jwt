// Package jwt implements a JWT middleware option for Vulcan proxy
// It will only parse tokens, putting all claims into a
// X-USER Header.
//
// Once added to your vctl binary,  you can `vctl jwt` for
// it's usage.
package jwt

// Note that I import the versions bundled with vulcand. That will make our lives easier, as we'll use exactly the same versions used
// by vulcand. We are escaping dependency management troubles thanks to Godep.
import (
	"bytes"
	"encoding/json"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/vulcand/oxy/utils"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"text/template"

	"github.com/mailgun/vulcand/plugin"
	"github.com/vulcand/vulcand/Godeps/_workspace/src/github.com/codegangsta/cli"
)

const (
	// Type of middleware
	Type = "jwt"
	// UserHeader is the header used to store user claims for
	// downstream services
	UserHeader = "X-USER"
)

// GetSpec is part of the Vulcan middleware interface
func GetSpec() *plugin.MiddlewareSpec {
	return &plugin.MiddlewareSpec{
		Type:      Type,       // A short name for the middleware
		FromOther: FromOther,  // Tells vulcand how to rcreate middleware from another one (this is for deserialization)
		FromCli:   FromCli,    // Tells vulcand how to create middleware from command line tool
		CliFlags:  CliFlags(), // Vulcand will add this flags to middleware specific command line tool
	}
}

// JwtMiddleware struct holds configuration parameters and is used to
// serialize/deserialize the configuration from storage engines.
type JwtMiddleware struct {
	PublicKey []byte
}

// JwtHandler is the HTTP handler for the JWT middleware
type JwtHandler struct {
	cfg  JwtMiddleware
	next http.Handler
}

// This function will be called each time the request hits the location with this middleware activated
func (a *JwtHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// Let OPTIONS go on by
	if r.Method == "OPTIONS" {
		a.next.ServeHTTP(w, r)
		return
	}
	keyfunc = func(token *jwt.Token) (interface{}, error) {
		return a.cfg.PublicKey, nil
	}
	token, err := jwt.ParseFromRequest(r, keyfunc)
	if err != nil {
		fmt.Printf("Token Error: %v\n", err)
		bw := &bufferWriter{header: make(http.Header), buffer: &bytes.Buffer{}}
		newBody := bytes.NewBufferString("")
		// We stop here, right?
		//a.next.ServeHTTP(bw, r)
		if err := applyString("{\"error\": \"forbidden\"}", newBody, r); err != nil {
			fmt.Errorf("can't write boddy")
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(newBody.Len()))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		utils.CopyHeaders(w.Header(), bw.Header())
		io.Copy(w, newBody)
		return
	}
	// Reject the request by writing forbidden response
	if !token.Valid {
		fmt.Errorf("error parsing Token : %v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	log.Printf("token: %v\n", token)
	log.Println(token.Claims)
	// Add the UserHeader to the Request
	claims, err := json.Marshal(token.Claims)
	if err != nil {
		log.Fatal("Cannot marshal claims to JSON")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.Header.Set(UserHeader, string(claims))

	// Pass the request to the next middleware in chain
	a.next.ServeHTTP(w, r)
}

// New is optional but handy, used to check input parameters when creating new middlewares
func New(publicKeyArray []byte) (*JwtMiddleware, error) {
	if len(publicKeyArray) == 0 {
		return nil, fmt.Errorf("please supply a public key")
	}
	return &JwtMiddleware{PublicKey: publicKeyArray}, nil
}

// NewHandler is important, it's called by vulcand to create a new handler from the middleware config and put it into the
// middleware chain. Note that we need to remember 'next' handler to call
func (c *JwtMiddleware) NewHandler(next http.Handler) (http.Handler, error) {
	return &JwtHandler{next: next, cfg: *c}, nil
}

// String() will be called by loggers inside Vulcand and command line tool.
func (c *JwtMiddleware) String() string {
	return fmt.Sprintf("key=%v", "********")
}

// FromOther Will be called by Vulcand when engine or API will read the middleware from the serialized format.
// It's important that the signature of the function will be exactly the same, otherwise Vulcand will
// fail to register this middleware.
// The first and the only parameter should be the struct itself, no pointers and other variables.
// Function should return middleware interface and error in case if the parameters are wrong.
func FromOther(c JwtMiddleware) (plugin.Middleware, error) {
	return New(c.PublicKey)
}

// FromCli constructs the middleware from the command line
func FromCli(c *cli.Context) (plugin.Middleware, error) {
	publicKeyFile := c.String("publicKeyFile")
	if publicKeyFile != "" {
		keyFile, err := ioutil.ReadFile(publicKeyFile)
		if err != nil {
			fmt.Println("File error")
		}
		return New([]byte(keyFile))
	}
	return nil, fmt.Errorf("please supply a public key file")
}

// CliFlags will be used by Vulcand construct help and CLI command for the vctl command
func CliFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{"publicKeyFile, pk", "", "Path to file with Public Key", ""},
	}
}

func applyString(in string, out io.Writer, request *http.Request) error {
	t, err := template.New("t").Parse(in)
	if err != nil {
		return err
	}

	if err = t.Execute(out, data{request}); err != nil {
		return err
	}

	return nil
}

type bufferWriter struct {
	header http.Header
	code   int
	buffer *bytes.Buffer
}

func (b *bufferWriter) Close() error {
	return nil
}

func (b *bufferWriter) Header() http.Header {
	return b.header
}

func (b *bufferWriter) Write(buf []byte) (int, error) {
	return b.buffer.Write(buf)
}

// WriteHeader sets rw.Code.
func (b *bufferWriter) WriteHeader(code int) {
	b.code = code
}

// data represents template data that is available to use in templates.
type data struct {
	Request *http.Request
}
