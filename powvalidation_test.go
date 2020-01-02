/*
 * Copyright 2019 Aletheia Ware LLC
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

package bcgo_test

import (
	"encoding/base64"
	"fmt"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/testinggo"
	"testing"
)

func TestPoWValidation(t *testing.T) {
	t.Run("HashAboveThreshold", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		channel := bcgo.OpenPoWChannel("TEST", 1)
		cache := makeMockCache(t)
		cache.Block[base64.RawURLEncoding.EncodeToString(hash)] = block
		testinggo.AssertNoError(t, channel.Update(cache, nil, hash, block))
	})
	t.Run("HashUnderThreshold", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		channel := bcgo.OpenPoWChannel("TEST", 1000)
		cache := makeMockCache(t)
		cache.Block[base64.RawURLEncoding.EncodeToString(hash)] = block
		testinggo.AssertError(t, fmt.Sprintf(bcgo.ERROR_CHAIN_INVALID, fmt.Sprintf(bcgo.ERROR_HASH_TOO_WEAK, 255, 1000)), channel.Update(cache, nil, hash, block))
	})
}
