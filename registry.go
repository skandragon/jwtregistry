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

	"github.com/lestrrat-go/jwx/jwa"
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
	keyset                jwk.Set
	signingKeyName        string
	signingValidityPeriod time.Duration
	clock                 jwt.Clock
}

var (
	registry map[string]*Context
	lock     sync.Mutex
	oncelock sync.Once
)

func findContext(name string) (c *Context, found bool) {
	lock.Lock()
	defer lock.Unlock()
	c, found = registry[name]
	return
}

func initOnce() {
	oncelock.Do(func() {
		registry = make(map[string]*Context)
	})
}

// Register creates a new Context, and stores it in the globally available
// registry under the provided named purpose.
//
// Various initial values are set using opts.  Once set, the objects
// used in these Options should be treated as immutable, as they will
// be accessed by multiple threads.
func Register(purpose string, issuer string, opts ...Option) error {
	initOnce()
	if len(purpose) == 0 {
		return fmt.Errorf("purpose must be provided")
	}

	if len(issuer) == 0 {
		return fmt.Errorf("issuer must be provided")
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

// Clear will erase all entries from the registry.
func Clear() {
	for k := range registry {
		delete(registry, k)
	}
}

func nowFromClock(clock jwt.Clock) time.Time {
	if clock == nil {
		return time.Now()
	}
	return clock.Now()
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
func Sign(purpose string, claims map[string]string, clock jwt.Clock) (signed []byte, err error) {
	initOnce()
	c, found := findContext(purpose)
	if !found {
		err = fmt.Errorf("context not found in registry")
		return
	}

	if len(c.signingKeyName) == 0 {
		err = fmt.Errorf("signing key not set")
		return
	}

	if c.keyset == nil || c.keyset.Len() == 0 {
		err = fmt.Errorf("keyset is empty")
		return
	}

	key, found := c.keyset.LookupKeyID(c.signingKeyName)
	if !found {
		err = fmt.Errorf("key is not in the keyset")
		return
	}

	now := nowFromClock(clock)
	builder := &jwt.Builder{}
	builder = builder.
		Claim(jwt.IssuerKey, c.issuer).
		Claim(jwt.IssuedAtKey, now)
	if c.signingValidityPeriod > 0 {
		builder = builder.Claim(jwt.ExpirationKey, now.Add(c.signingValidityPeriod))
	}

	t, err := builder.Build()
	if err != nil {
		return
	}

	for k, v := range claims {
		if err = t.Set(k, v); err != nil {
			return
		}
	}

	signed, err = jwt.Sign(t, jwa.SignatureAlgorithm(key.Algorithm()), key)
	return
}

// Validate will validate the intregrity a given JWT using the named Context's
// validation configuration.  The issuer and start time are always
// validated, and if the expiration time is present it will be
// included.  A map containing all the claims will be returned.
func Validate(purpose string, signed []byte, clock jwt.Clock) (claims map[string]string, err error) {
	initOnce()
	c, found := findContext(purpose)
	if !found {
		err = fmt.Errorf("context not found in registry")
		return
	}

	if c.keyset == nil || c.keyset.Len() == 0 {
		err = fmt.Errorf("keyset is empty")
		return
	}

	opts := []jwt.ParseOption{
		jwt.WithValidate(true),
		jwt.WithIssuer(c.issuer),
		jwt.WithKeySet(c.keyset),
	}
	if clock != nil {
		opts = append(opts, jwt.WithClock(clock))
	}

	t, err := jwt.Parse(signed, opts...)
	if err != nil {
		return
	}

	claims = make(map[string]string)
	for k, v := range t.PrivateClaims() {
		claims[k] = fmt.Sprintf("%v", v)
	}
	return
}
