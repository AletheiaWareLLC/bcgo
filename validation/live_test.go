/*
 * Copyright 2020-21 Aletheia Ware LLC
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
	"testing"
)

func TestLiveValidation(t *testing.T) {
	t.Run("Set", func(t *testing.T) {
		testinggo.SetEnv(t, bcgo.LIVE_FLAG, "foo")
		defer testinggo.UnsetEnv(t, bcgo.LIVE_FLAG)
		block := test.NewMockBlock(t, 1234)
		record := test.NewMockRecord(t)
		record.Meta = map[string]string{
			bcgo.LIVE_FLAG: "foo",
		}
		block.Entry = []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				RecordHash: test.NewHash(t, record),
				Record:     record,
			},
		}
		hash := test.NewHash(t, block)
		channel := channel.New("TEST")
		channel.AddValidator(&validation.Live{})
		cache := test.NewMockCache(t)
		cache.PutBlock(hash, block)
		testinggo.AssertNoError(t, channel.Update(cache, nil, hash, block))
	})
	t.Run("Unset", func(t *testing.T) {
		testinggo.SetEnv(t, bcgo.LIVE_FLAG, "foo")
		defer testinggo.UnsetEnv(t, bcgo.LIVE_FLAG)
		block := test.NewMockBlock(t, 1234)
		record := test.NewMockRecord(t)
		block.Entry = []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				RecordHash: test.NewHash(t, record),
				Record:     record,
			},
		}
		hash := test.NewHash(t, block)
		channel := channel.New("TEST")
		channel.AddValidator(&validation.Live{})
		cache := test.NewMockCache(t)
		cache.PutBlock(hash, block)
		testinggo.AssertError(t, bcgo.ErrChainInvalid{Reason: validation.ErrDifferentLiveFlag{Expected: "foo", Actual: ""}.Error()}.Error(), channel.Update(cache, nil, hash, block))
	})
}
