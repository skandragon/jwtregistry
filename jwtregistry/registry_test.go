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
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegister(t *testing.T) {
	keyset := jwk.NewSet()
	keyset.Add(jwk.NewSymmetricKey())

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
		{
			"WithClock works",
			args{
				"foo",
				"flame",
				[]Option{WithClock(&TimeClock{9999})},
			},
			"",
			&Context{
				purpose: "foo",
				issuer:  "flame",
				clock:   &TimeClock{9999},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Register(tt.args.purpose, tt.args.issuer, tt.args.opts...)
			if tt.wantErrorMsg != "" {
				require.EqualError(t, err, tt.wantErrorMsg)
			} else {
				require.NoError(t, err)
				c, found := findContext(tt.args.purpose)
				log.Printf("%v %v", found, c)
				require.True(t, found, "could not find context")
				assert.Equal(t, tt.want, c)
			}
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

func TestSign(t *testing.T) {
	key1, err := jwk.New([]byte("abcd1234"))
	require.NoError(t, err)
	err = key1.Set(jwk.KeyIDKey, "key1")
	require.NoError(t, err)
	err = key1.Set(jwk.AlgorithmKey, jwa.HS256)
	require.NoError(t, err)

	keyset := jwk.NewSet()
	added := keyset.Add(key1)
	require.True(t, added)

	type args struct {
		purpose string
		claims  map[string]string
	}
	tests := []struct {
		name       string
		args       args
		wantSigned []byte
		wantErr    bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSigned, err := Sign(tt.args.purpose, tt.args.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSigned, tt.wantSigned) {
				t.Errorf("Sign() = %v, want %v", gotSigned, tt.wantSigned)
			}
		})
	}
}
