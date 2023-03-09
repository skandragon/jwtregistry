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
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// Option specifies non-default overrides at
// creation time.
type Option func(*Context)

// WithKeyset specifies the keyset (named keys) to be used for signing or
// validating.  This keyset is used as a list of possible keys to validate
// JWTs, as well as selecting which named key to use when signing.
func WithKeyset(keyset jwk.Set) Option {
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
