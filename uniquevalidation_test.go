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

func TestUniqueValidation(t *testing.T) {
	t.Run("Unique", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		channel := &bcgo.Channel{
			Name: "TEST",
			Validators: []bcgo.Validator{
				&bcgo.UniqueValidator{},
			},
		}
		cache := makeMockCache(t)
		cache.PutBlock(hash, block)
		testinggo.AssertNoError(t, channel.Update(cache, nil, hash, block))
	})
	t.Run("Duplicate Block", func(t *testing.T) {
		// TODO need to build block, then build linked block and mine it until the hashes are the same
	})
	t.Run("Duplicate Entry", func(t *testing.T) {
		record := makeRecord(t)
		eh := makeHash(t, record)
		block := makeBlock(t, 1234)
		block.Entry = []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				RecordHash: eh,
				Record:     record,
			},
			&bcgo.BlockEntry{
				RecordHash: eh,
				Record:     record,
			},
		}
		hash := makeHash(t, block)
		channel := &bcgo.Channel{
			Name: "TEST",
			Validators: []bcgo.Validator{
				&bcgo.UniqueValidator{},
			},
		}
		cache := makeMockCache(t)
		cache.PutBlock(hash, block)
		testinggo.AssertError(t, fmt.Sprintf(bcgo.ERROR_CHAIN_INVALID, fmt.Sprintf(bcgo.ERROR_DUPLICATE_ENTRY, base64.RawURLEncoding.EncodeToString(eh))), channel.Update(cache, nil, hash, block))
	})
}
