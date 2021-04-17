/*
 * Copyright 2021 Aletheia Ware LLC
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

package test

import (
	"aletheiaware.com/bcgo"
	"testing"
)

func NewMockBlock(t *testing.T, timestamp uint64) *bcgo.Block {
	t.Helper()
	return &bcgo.Block{
		Timestamp:   timestamp,
		ChannelName: "TEST",
		Length:      1,
	}
}

func NewMockLinkedBlock(t *testing.T, timestamp uint64, prevHash []byte, prevBlock *bcgo.Block) *bcgo.Block {
	t.Helper()
	return &bcgo.Block{
		Timestamp:   timestamp,
		ChannelName: "TEST",
		Length:      prevBlock.Length + 1,
		Previous:    prevHash,
	}
}
