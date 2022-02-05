/*
 * Copyright 2022 Michael Graff.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jwtregistry

import (
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

// Context holds a named JWT signer, validator, and other configuration
// for a specific named JWT use/purpose.
//
// Once created, these should be treated as immutable.  If changing a
// registry's configuration is desired, New() should be called to recreate
// it entirely.  This keeps things thread-safe.
type Context struct {
	purpose               string
	issuer                string
	keyset                *jwk.Set
	signingKeyName        string
	signingValidityPeriod time.Duration
	clock                 jwt.Clock
}

// Option specifies non-default overrides at
// creation time.
type Option func(*Context)

var (
	registry map[string]*Context
	lock     sync.Mutex
)

// Register creates a new Context, and stores it in the globally available
// registry under the provided named purpose.
//
// Various initial values are set using opts.  Once set, the objects
// used in these Options should be treated as immutable, as they will
// be accessed by multiple threads.
func Register(purpose string, issuer string, opts ...Option) error {
	if len(purpose) == 0 {
		return fmt.Errorf("Purpose must be provided")
	}

	if len(issuer) == 0 {
		return fmt.Errorf("Issuer must be provided")
	}

	r := &Context{
		purpose: purpose,
		issuer:  issuer,
		clock:   &TimeClock{},
	}

	for _, opt := range opts {
		opt(r)
	}

	lock.Lock()
	defer lock.Unlock()
	registry[purpose] = r
	return nil
}

// Delete deletes a named Context from the registry.
func Delete(purpose string) {
	lock.Lock()
	defer lock.Unlock()
	delete(registry, purpose)
}

// Sign will create a new JWT based on the map of input data,
// the Context's configuration, and current signing key.  If the
// signing key name is not set, an error will be returned.
// The issuer ("iss") will be set from the name provided at creation
// time, and inception ("iat") will always be set to whatever
// the provided clock returns as Now().  If a duration is configured,
// expirtation ("exp") will also be added to the claims.
//
// Additional claims provided will also be added prior to signing.
func Sign(purpose string, claims map[string]string) (string, error) {
	return "", fmt.Errorf("Not yet implemented")
}

// Validate will validate the intregrity a given JWT using the named Context's
// validation configuration.  The issuer and start time are always
// validated, and if the expiration time is present it will be
// included.  A map containing all the claims will be returned.
func Validate(purpose string, token string) (map[string]string, error) {
	return map[string]string{}, fmt.Errorf("Not yet implemented")
}

// WithKeyset specifies the keyset (named keys) to be used for signing or
// validating.  This keyset is used as a list of possible keys to validate
// JWTs, as well as selecting which named key to use when signing.
func WithKeyset(keyset *jwk.Set) Option {
	return func(jr *Context) {
		jr.keyset = keyset
	}
}

// WithSigningKeyName selects a key from one of the keys passed into WithKeyset
// to sign new requests.  If signing is not needed, setting this is not required.
func WithSigningKeyName(name string) Option {
	return func(jr *Context) {
		jr.signingKeyName = name
	}
}

// WithSigningValidityPeriod sets the time between the issued time and the
// expiry time.  If set to 0, no expiration time is set when signing.
// If a JWT has an expiration time, it will be validated regardless of this
// duration.
func WithSigningValidityPeriod(d time.Duration) Option {
	return func(jr *Context) {
		jr.signingValidityPeriod = d
	}
}
