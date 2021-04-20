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

package validation_test

import (
	"aletheiaware.com/bcgo"
	"aletheiaware.com/bcgo/channel"
	"aletheiaware.com/bcgo/test"
	"aletheiaware.com/bcgo/validation"
	"aletheiaware.com/testinggo"
	"encoding/base64"
	"testing"
)

func TestUniqueValidation(t *testing.T) {
	t.Run("Unique", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		channel := channel.New("TEST")
		channel.AddValidator(&validation.Unique{})
		cache := test.NewMockCache(t)
		cache.PutBlock(hash, block)
		testinggo.AssertNoError(t, channel.Update(cache, nil, hash, block))
	})
	t.Run("Duplicate Block", func(t *testing.T) {
		// TODO need to build block, then build linked block and mine it until the hashes are the same
	})
	t.Run("Duplicate Entry", func(t *testing.T) {
		record := test.NewMockRecord(t)
		eh := test.NewHash(t, record)
		block := test.NewMockBlock(t, 1234)
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
		hash := test.NewHash(t, block)
		channel := channel.New("TEST")
		channel.AddValidator(&validation.Unique{})
		cache := test.NewMockCache(t)
		cache.PutBlock(hash, block)
		testinggo.AssertError(t, bcgo.ErrChainInvalid{Reason: validation.ErrDuplicateEntry{Hash: base64.RawURLEncoding.EncodeToString(eh)}.Error()}.Error(), channel.Update(cache, nil, hash, block))
	})
}
