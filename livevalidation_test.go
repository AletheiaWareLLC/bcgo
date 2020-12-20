/*
 * Copyright 2020 Aletheia Ware LLC
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
	"fmt"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/testinggo"
	"testing"
)

func TestLiveValidation(t *testing.T) {
	t.Run("Set", func(t *testing.T) {
		testinggo.MakeEnv(t, bcgo.LIVE_FLAG, "foo")
		defer testinggo.UnmakeEnv(t, bcgo.LIVE_FLAG)
		block := makeBlock(t, 1234)
		record := makeRecord(t)
		record.Meta = map[string]string{
			bcgo.LIVE_FLAG: "foo",
		}
		block.Entry = []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				RecordHash: makeHash(t, record),
				Record:     record,
			},
		}
		hash := makeHash(t, block)
		channel := &bcgo.Channel{
			Name: "TEST",
			Validators: []bcgo.Validator{
				&bcgo.LiveValidator{},
			},
		}
		cache := makeMockCache(t)
		cache.PutBlock(hash, block)
		testinggo.AssertNoError(t, channel.Update(cache, nil, hash, block))
	})
	t.Run("Unset", func(t *testing.T) {
		testinggo.MakeEnv(t, bcgo.LIVE_FLAG, "foo")
		defer testinggo.UnmakeEnv(t, bcgo.LIVE_FLAG)
		block := makeBlock(t, 1234)
		record := makeRecord(t)
		block.Entry = []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				RecordHash: makeHash(t, record),
				Record:     record,
			},
		}
		hash := makeHash(t, block)
		channel := &bcgo.Channel{
			Name: "TEST",
			Validators: []bcgo.Validator{
				&bcgo.LiveValidator{},
			},
		}
		cache := makeMockCache(t)
		cache.PutBlock(hash, block)
		testinggo.AssertError(t, fmt.Sprintf(bcgo.ERROR_CHAIN_INVALID, fmt.Sprintf(bcgo.ERROR_DIFFERENT_LIVE_FLAG, "foo", "")), channel.Update(cache, nil, hash, block))
	})
}
