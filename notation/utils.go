/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package notation

import (
	"reflect"
	"time"
)

// resolveTimeout returns timeout when it is positive, otherwise it falls back
// to fallback.
func resolveTimeout(timeout, fallback time.Duration) time.Duration {
	if timeout <= 0 {
		return fallback
	}
	return timeout
}

// isNil reports whether an interface value is nil or wraps a nil pointer (typed
// nil), which a plain == nil comparison would miss.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}
