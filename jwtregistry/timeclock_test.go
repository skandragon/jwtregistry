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
	"testing"
	"time"
)

func TestTimeClock_Now(t *testing.T) {
	type fields struct {
		NowTime int64
	}
	tests := []struct {
		name   string
		fields fields
		want   time.Time
	}{
		{
			"default",
			fields{},
			time.Now(),
		},
		{
			"locked clock to 50",
			fields{50},
			time.Unix(50, 0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &TimeClock{
				NowTime: tt.fields.NowTime,
			}
			got := tc.Now()
			if got.Unix() < tt.want.Add(-1*time.Second).Unix() || got.Unix() > tt.want.Add(1*time.Second).Unix() {
				t.Errorf("TimeClock.Now() = %v, want %v", got, tt.want)
			}
		})
	}
}
