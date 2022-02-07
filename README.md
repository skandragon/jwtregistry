# Go jwtregistry

[![Go Report Card](https://goreportcard.com/badge/github.com/skandragon/jwtregistry)](https://goreportcard.com/report/github.com/skandragon/jwtregistry)

A hopefully simple JWT signing and validating registry that can be
used globally, referring to signing and validating contexts by named
purpose.

This was created to simplify code that uses many different JWT
issuers and validators, and needs to update their contents based
on changed configuration.

All values returned by the methods are thread-safe.  Values like keysets
provided during context creation must not be modfied after registration.

To update a named context, register a new one with the same name.

Not all validation options are provided, and sensible (opinionated)
validations and crypto algorithms used.

# Dependencies

This is built on top of `github.com/lestrrat-go/jwx` version 1, and uses
that package's versions of a keyset, key, and optional clock used to sign
or validate tokens.

# Usage

## Register a context

Before use, a context must be registered.  Once added, it can
be used anywhere using just the name.

The `keyset` and any other options passed in should be treated
as immutable.

```go
// make sure you add error checking.
key1, err := jwk.New([]byte("abcd1234"))
err = key1.Set(jwk.KeyIDKey, "key1")
err = key1.Set(jwk.AlgorithmKey, jwa.HS256)

keyset := jwk.NewSet()
added := keyset.Add(key1)

err = jwtregistry.Register(
    "web",
    "flame",
    WithKeyset(keyset),
    WithSigningKeyName("key1"),
)
```

## Signing

```go
claims := map[string]string{"userid": "1234"}
signed, err := Sign("web", claims, nil)
```

If no error is returned, `signed` will be a signed JWT with the
additional claims added.  If the context has a validity
duration set, it will also have an expiration time after which
it will no longer validate.  It always has a start time, and
an issuer set.  All three standard fields will be verified
by `Validate()`

## Validation

```go
claims, err := Validate("web", token, nil)
```

If there is no error, `claims` will contain the non-standard ("private") claims in the token.

## Testing and the Clock

For testing purposes, `Sign()` and `Validate()` accept a
`jwt.Clock` which must implement `Now() time.Time`.
An example of this would be `jwtregistry.TimeClock{1234}`.
