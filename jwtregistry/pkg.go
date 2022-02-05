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

// Package jwtregistry provides a way to store the current keys
// to be used for creating and validating JWTs.  Multiple
// purposes can be used, each of which has a "keyset",
// "current key", and parameters such as expiry time,
// issuer to set, default validation options, and other
// usually unchanging items.
//
// These registries would usually be created once, and
// used many times.  Passing this deeply into each method
// is a pain...  which this package hopes to reduce.
//
package jwtregistry
