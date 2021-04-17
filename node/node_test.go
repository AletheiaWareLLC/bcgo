/*
 * Copyright 2019-21 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package node_test

import (
	"aletheiaware.com/bcgo"
	"aletheiaware.com/bcgo/node"
	"aletheiaware.com/bcgo/test"
	"aletheiaware.com/testinggo"
	"testing"
)

func TestNodeWrite(t *testing.T) {
	t.Run("PayloadTooBig", func(t *testing.T) {
		cache := test.NewMockCache(t)
		node := node.New(
			test.NewMockAccount(t, test.Alias),
			cache,
			nil,
		)
		channel := test.NewMockChannel(t)
		payload := make([]byte, bcgo.MAX_PAYLOAD_SIZE_BYTES+1)
		_, err := node.Write(0, channel, nil, nil, payload)
		testinggo.AssertError(t, "Payload too large: 10MiB max: 10MiB", err)
		if len(cache.Entries) != 0 {
			t.Fatalf("Entry written to cache")
		}
	})
}
