# JWT Middleware for Vulcan Proxy
This is an attempt at creating a simple [JWT](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) middleware for [Vulcan Proxy](http://vulcanproxy.com)

## Caveats
I hate to start with the negative, but:
* I am pretty new to Go, so there's that
* I am pretty new to Vulcan, so there's that too
* I am scratching an itch, so if my itch didn't touch part of the JWT spec, I didn't scratch it. (A good example is generating a JWT key. We don't need it yet, so it's not here)

## Install
```
go get github.com/skookum/vulcan-jwt
```

## Usage
This presumes you have built new `vulcand` and `vctl` binaries per [the instructions](http://vulcanproxy.com/middlewares.html#example-auth-middleware). Basically, you should be able to add `github.com/skookum/vulcan-jwt` to your registry and build your `vulcand` and `vctl` binaries.

1. Create public and private key files:
```
openssl genrsa -out jwt_test.rsa 1024
openssl rsa -in jwt_test.rsa -pubout > jwt_test.rsa.pub
```

2. Add the middleware
```
vctl jst upsert -id=jwt_middleware -f someFrontend -publicKeyFile=jwt_test.rsa.pub --vulcan=http://yourvulcanhost
```
(`-id` can be whatever you want to call the instance of the middleware)

3. Make JWT enabled requests! The middleware looks for the `Authorization` header on requests in a `Bearer: <tokenstring>` format. Also, it will put the decoded claims into the `X-USER` header. The downstream services can use this header to get user info.

If you're wondering, we are using a standalone authentication service to create the token. Obviously, the private key you generate for your middleware needs to be used to crewate the public key used for this middleware.

### Remove
```
vctl jwt rm -id=jwt_middeware -f someFrontend --vulcan=http://yourvulcanhost
```

## Roadmap
* Possibly add CLI parameter to allow unauthorized requests
* Possible add generation
* Clean it up as my Go goes

## Contributing
1. Write tests
2. Write code
3. Run tests until they pass
4. Issue PR
