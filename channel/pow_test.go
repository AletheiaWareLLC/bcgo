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

package channel_test

import (
	"aletheiaware.com/bcgo"
	"aletheiaware.com/bcgo/channel"
	"aletheiaware.com/bcgo/test"
	"aletheiaware.com/bcgo/validation"
	"aletheiaware.com/testinggo"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestPoW(t *testing.T) {
	t.Run("HashAboveThreshold", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		channel := channel.NewPoW("TEST", 1)
		cache := test.NewMockCache(t)
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash)] = block
		testinggo.AssertNoError(t, channel.Update(cache, nil, hash, block))
	})
	t.Run("HashUnderThreshold", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		channel := channel.NewPoW("TEST", 1000)
		cache := test.NewMockCache(t)
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash)] = block
		testinggo.AssertError(t, fmt.Sprintf(bcgo.ERROR_CHAIN_INVALID, fmt.Sprintf(validation.ERROR_HASH_TOO_WEAK, 255, 1000)), channel.Update(cache, nil, hash, block))
	})
}
