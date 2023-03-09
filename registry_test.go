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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func GenerateSymmetricKey() []byte {
	sharedKey := make([]byte, 64)
	rand.Read(sharedKey)
	return sharedKey
}

func GenerateSymmetricJwk() (jwk.Key, error) {
	key, err := jwk.FromRaw(GenerateSymmetricKey())
	if err != nil {
		return nil, fmt.Errorf(`failed to generate jwk.SymmetricKey: %w`, err)
	}

	return key, nil
}

func TestRegister(t *testing.T) {
	keyset := jwk.NewSet()
	key, err := GenerateSymmetricJwk()
	if err != nil {
		log.Fatalf("cannot generate key: %v", err)
	}
	keyset.AddKey(key)

	type args struct {
		purpose string
		issuer  string
		opts    []Option
	}
	tests := []struct {
		name         string
		args         args
		wantErrorMsg string
		want         *Context
	}{
		{
			"no options",
			args{
				"foo",
				"flame",
				[]Option{},
			},
			"",
			&Context{
				purpose: "foo",
				issuer:  "flame",
				clock:   &TimeClock{0},
			},
		},
		{
			"empty purpose errors",
			args{
				"",
				"flame",
				[]Option{},
			},
			"purpose must be provided",
			nil,
		},
		{
			"empty issuer errors",
			args{
				"foo",
				"",
				[]Option{},
			},
			"issuer must be provided",
			nil,
		},
		{
			"WithKeyset works",
			args{
				"foo",
				"flame",
				[]Option{WithKeyset(keyset)},
			},
			"",
			&Context{
				purpose: "foo",
				issuer:  "flame",
				clock:   &TimeClock{0},
				keyset:  keyset,
			},
		},
		{
			"WithSigningKeyName works",
			args{
				"foo",
				"flame",
				[]Option{WithSigningKeyName("key1")},
			},
			"",
			&Context{
				purpose:        "foo",
				issuer:         "flame",
				clock:          &TimeClock{0},
				signingKeyName: "key1",
			},
		},
		{
			"WithSigningValidityPeriod works",
			args{
				"foo",
				"flame",
				[]Option{WithSigningValidityPeriod(1 * time.Hour)},
			},
			"",
			&Context{
				purpose:               "foo",
				issuer:                "flame",
				clock:                 &TimeClock{0},
				signingValidityPeriod: 1 * time.Hour,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Register(tt.args.purpose, tt.args.issuer, tt.args.opts...)
			if tt.wantErrorMsg != "" {
				require.EqualError(t, err, tt.wantErrorMsg)
				return
			}
			require.NoError(t, err)
			c, found := findContext(tt.args.purpose)
			require.True(t, found, "could not find context")
			assert.Equal(t, tt.want, c)
		})
	}
}

func TestDelete(t *testing.T) {
	registry = map[string]*Context{
		"foo": {},
	}
	c, found := findContext("foo")
	require.True(t, found)
	require.NotNil(t, c)
	Delete("foo")
	c, found = findContext("foo")
	require.False(t, found)
	require.Nil(t, c)
}

func setupKeys(t *testing.T) {
	key1, err := jwk.FromRaw([]byte("abcd1234"))
	require.NoError(t, err)
	err = key1.Set(jwk.KeyIDKey, "key1")
	require.NoError(t, err)
	err = key1.Set(jwk.AlgorithmKey, jwa.HS256)
	require.NoError(t, err)

	keyset := jwk.NewSet()
	err = keyset.AddKey(key1)
	require.NoError(t, err)

	Clear()
	err = Register("noKeyset", "flame", WithSigningKeyName("key1"))
	require.NoError(t, err)
	err = Register("noSigningKeyNameSet", "flame", WithKeyset(keyset))
	require.NoError(t, err)
	err = Register("wrongKeyName", "flame", WithKeyset(keyset), WithSigningKeyName("notthere"))
	require.NoError(t, err)
	err = Register("noExpiry", "flame", WithKeyset(keyset), WithSigningKeyName("key1"))
	require.NoError(t, err)
	err = Register("expiry", "flame", WithKeyset(keyset), WithSigningKeyName("key1"), WithSigningValidityPeriod(1*time.Minute))
	require.NoError(t, err)
	err = Register("wrongIssuer", "not-flame", WithKeyset(keyset), WithSigningKeyName("key1"))
	require.NoError(t, err)
}

func TestSign(t *testing.T) {
	setupKeys(t)
	t.Parallel()
	type args struct {
		purpose string
		claims  map[string]string
	}
	tests := []struct {
		name          string
		args          args
		wantClaims    string
		wantErrString string
	}{
		{
			"noSuchContext",
			args{
				"noSuchContext",
				map[string]string{},
			},
			"",
			"context not found in registry",
		},
		{
			"noKeyset",
			args{
				"noKeyset",
				map[string]string{},
			},
			"",
			"keyset is empty",
		},
		{
			"wrongKeyName",
			args{
				"wrongKeyName",
				map[string]string{},
			},
			"",
			"key is not in the keyset",
		},
		{
			"noSigningKeyNameSet",
			args{
				"noSigningKeyNameSet",
				map[string]string{},
			},
			"",
			"signing key not set",
		},
		{
			"noExpiry",
			args{
				"noExpiry",
				map[string]string{},
			},
			`{"iat": 1111,"iss":"flame"}`,
			"",
		},
		{
			"expiry",
			args{
				"expiry",
				map[string]string{},
			},
			`{"iat": 1111,"exp": 1171, "iss":"flame"}`,
			"",
		},
		{
			"extraClaims",
			args{
				"noExpiry",
				map[string]string{"foo": "bar"},
			},
			`{"iat": 1111,"iss":"flame","foo":"bar"}`,
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSigned, err := Sign(tt.args.purpose, tt.args.claims, &TimeClock{1111})
			log.Printf("%s %s", tt.name, string(gotSigned))
			if len(tt.wantErrString) != 0 {
				require.EqualError(t, err, tt.wantErrString)
				return
			}
			require.NoError(t, err)
			// check that the claims are as we expect
			parts := strings.Split(string(gotSigned), ".")
			claims, err := base64.RawStdEncoding.DecodeString(parts[1])
			require.NoError(t, err)
			assert.JSONEq(t, tt.wantClaims, string(claims))
		})
	}
}

func TestValidate(t *testing.T) {
	setupKeys(t)
	t.Parallel()
	type args struct {
		purpose string
		signed  []byte
	}
	tests := []struct {
		name          string
		args          args
		clock         jwt.Clock
		wantClaims    map[string]string
		wantErrString string
	}{
		{
			"noSuchContext",
			args{
				"noSuchContext",
				[]byte{},
			},
			&TimeClock{1111},
			nil,
			"context not found in registry",
		},
		{
			"noKeyset",
			args{
				"noKeyset",
				[]byte{},
			},
			&TimeClock{1111},
			nil,
			"keyset is empty",
		},
		{
			"noExpiry used after start",
			args{
				"noExpiry",
				// signed at 1111 time
				[]byte("eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6ImZsYW1lIn0.rIapXyq6R2DEtFr10_lfGLXamU0Jn7yfHRgAtkOsD84"),
			},
			&TimeClock{2222},
			map[string]string{},
			"",
		},
		{
			"noExpiry used before",
			args{
				"noExpiry",
				// signed at 1111 time
				[]byte("eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjExMTEsImlzcyI6ImZsYW1lIn0.rIapXyq6R2DEtFr10_lfGLXamU0Jn7yfHRgAtkOsD84"),
			},
			&TimeClock{50},
			nil,
			`"iat" not satisfied`,
		},
		{
			"expiry used after expired",
			args{
				"expiry",
				// signed at 1111 time
				[]byte("eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjExNzEsImlhdCI6MTExMSwiaXNzIjoiZmxhbWUifQ.I8DapiMGKPWi84R_6BhvJYRJVouFtv5Mb0cvgjRIwe4"),
			},
			&TimeClock{10000},
			nil,
			`"exp" not satisfied`,
		},
		{
			"custom claims",
			args{
				"noExpiry",
				// signed at 1111 time
				[]byte("eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJmb28iOiJiYXIiLCJpYXQiOjExMTEsImlzcyI6ImZsYW1lIn0.MbasnICK6iYP62cO3XjOgOp7Jagayv-HhPjamueCjzk"),
			},
			&TimeClock{2222},
			map[string]string{"foo": "bar"},
			"",
		},
		{
			"wrong issuer",
			args{
				"wrongIssuer",
				[]byte("eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEiLCJ0eXAiOiJKV1QifQ.eyJmb28iOiJiYXIiLCJpYXQiOjExMTEsImlzcyI6ImZsYW1lIn0.MbasnICK6iYP62cO3XjOgOp7Jagayv-HhPjamueCjzk"),
			},
			&TimeClock{2222},
			map[string]string{},
			`"iss" not satisfied: values do not match`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotClaims, err := Validate(tt.args.purpose, tt.args.signed, tt.clock)
			if len(tt.wantErrString) != 0 {
				require.EqualError(t, err, tt.wantErrString)
				return
			}
			require.NoError(t, err)
			require.Equal(t, gotClaims, tt.wantClaims)
		})
	}
}

func timeEqualsEpislion(want time.Time, got time.Time, fudge time.Duration) bool {
	return got.Unix() >= want.Add(-fudge).Unix() && got.Unix() <= want.Add(fudge).Unix()
}

func Test_nowFromClock(t *testing.T) {
	type args struct {
		clock jwt.Clock
	}
	tests := []struct {
		name string
		args args
		want time.Time
	}{
		{"nil", args{nil}, time.Now()},
		{"set at 50", args{&TimeClock{50}}, time.Unix(50, 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nowFromClock(tt.args.clock)
			if !timeEqualsEpislion(tt.want, got, 1*time.Second) {
				t.Errorf("nowFromClock() = %v, want %v", got, tt.want)
			}
		})
	}
}
