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

import "time"

// TimeClock implements the jwt.Clock interface, allowing control over
// the interpretation of 'current time' used during validating and signing.
// If NowTime is let unset (0), time.Now() return value will be used.
// Unix time (in seconds).
//
// This is included to help test expiration and use before inception.
type TimeClock struct {
	NowTime int64
}

// Now returns either the specific time used at context creation, or
// time.Now().
func (tc *TimeClock) Now() time.Time {
	if tc.NowTime != 0 {
		return time.Unix(tc.NowTime, 0)
	}
	return time.Now()
}
