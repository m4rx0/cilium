// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logging

import (
	"golang.org/x/time/rate"
)

type Limiter struct {
	*rate.Limiter
}

func NewLimiter(r rate.Limit, b int) Limiter {
	return Limiter{
		Limiter: rate.NewLimiter(r, b),
	}
}

func (ll Limiter) Allow() bool {
	if ll.Limiter == nil {
		return true // limiter not initialized => no limit
	}
	return ll.Limiter.Allow()
}
