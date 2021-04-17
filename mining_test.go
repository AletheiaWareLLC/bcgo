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

package bcgo_test

import (
	"aletheiaware.com/bcgo"
	"aletheiaware.com/bcgo/node"
	"aletheiaware.com/bcgo/test"
	"aletheiaware.com/cryptogo"
	"aletheiaware.com/testinggo"
	"bytes"
	"encoding/base64"
	"testing"
)

func TestLastMinedTimestamp(t *testing.T) {
	t.Run("NoHead", func(t *testing.T) {
		cache := test.NewMockCache(t)
		node := node.New(
			test.NewMockAccount(t, test.Alias),
			cache,
			nil,
		)
		channel := test.NewMockChannel(t)

		time, err := bcgo.LastMinedTimestamp(node, channel)
		testinggo.AssertNoError(t, err)
		if time != 0 {
			t.Fatalf("Incorrect timestamp; expected 0 instead got '%d'", time)
		}
	})

	t.Run("LastBlock", func(t *testing.T) {
		cache := test.NewMockCache(t)
		node := node.New(
			test.NewMockAccount(t, test.Alias),
			cache,
			nil,
		)

		block := &bcgo.Block{
			Timestamp:   1234,
			ChannelName: "TEST",
			Length:      1,
			Miner:       node.Account().Alias(),
		}
		hash := test.NewHash(t, block)
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash)] = block

		channel := test.NewMockChannel(t)
		channel.Set(1234, hash)

		time, err := bcgo.LastMinedTimestamp(node, channel)
		testinggo.AssertNoError(t, err)
		if time != 1234 {
			t.Fatalf("Incorrect timestamp; expected 1234 instead got '%d'", time)
		}
	})

	t.Run("FirstBlock", func(t *testing.T) {
		cache := test.NewMockCache(t)
		node := node.New(
			test.NewMockAccount(t, test.Alias),
			cache,
			nil,
		)

		block := &bcgo.Block{
			Timestamp:   1234,
			ChannelName: "TEST",
			Length:      1,
			Miner:       node.Account().Alias(),
		}
		hash := test.NewHash(t, block)
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash)] = block

		block2 := &bcgo.Block{
			Timestamp:   5678,
			ChannelName: "TEST",
			Length:      2,
			Previous:    hash,
			Miner:       "bob",
		}
		hash2 := test.NewHash(t, block2)
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash2)] = block2

		channel := test.NewMockChannel(t)
		channel.Set(5678, hash2)

		time, err := bcgo.LastMinedTimestamp(node, channel)
		testinggo.AssertNoError(t, err)
		if time != 1234 {
			t.Fatalf("Incorrect timestamp; expected 1234 instead got '%d'", time)
		}
	})
}

func TestMine(t *testing.T) {
	t.Run("BlockTooBig", func(t *testing.T) {
		cache := test.NewMockCache(t)
		node := node.New(
			test.NewMockAccount(t, test.Alias),
			cache,
			nil,
		)

		r := &bcgo.Record{
			Payload: make([]byte, bcgo.MAX_BLOCK_SIZE_BYTES+1),
		}
		rh, err := cryptogo.HashProtobuf(r)
		testinggo.AssertNoError(t, err)
		cache.Entries["TEST"] = []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				Record:     r,
				RecordHash: rh,
			},
		}

		channel := test.NewMockChannel(t)
		_, _, err = bcgo.Mine(node, channel, bcgo.THRESHOLD_I, nil)
		testinggo.AssertError(t, "Block too large: 2GiB max: 2GiB", err)
	})

	t.Run("ChannelHead", func(t *testing.T) {
		cache := test.NewMockCache(t)
		node := node.New(
			test.NewMockAccount(t, test.Alias),
			cache,
			nil,
		)

		block1 := &bcgo.Block{
			Timestamp:   1234,
			ChannelName: "TEST",
			Length:      1,
			Miner:       node.Account().Alias(),
		}
		hash1 := test.NewHash(t, block1)
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash1)] = block1

		r := &bcgo.Record{
			Payload: []byte("FooBar"),
		}
		rh, err := cryptogo.HashProtobuf(r)
		testinggo.AssertNoError(t, err)
		cache.Entries["TEST"] = []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				Record:     r,
				RecordHash: rh,
			},
		}

		channel := test.NewMockChannel(t)
		channel.Set(1234, hash1)
		hash2, block2, err := bcgo.Mine(node, channel, bcgo.THRESHOLD_I, nil)
		testinggo.AssertNoError(t, err)
		if hash2 == nil {
			t.Fatalf("Mined block hash is nil")
		}
		if block2 == nil {
			t.Fatalf("Mined block is nil")
		}
		if block2.Length != 2 {
			t.Fatalf("Incorrect length; expected 2, got '%d'", block2.Length)
		}
		if !bytes.Equal(block2.Previous, hash1) {
			t.Fatalf("Incorrect previous; expected '%s', got '%s", base64.RawURLEncoding.EncodeToString(hash1), base64.RawURLEncoding.EncodeToString(block2.Previous))
		}
		if alias := node.Account().Alias(); block2.Miner != alias {
			t.Fatalf("Incorrect miner; expected '%s', got '%s'", alias, block2.Miner)
		}
		if len(block2.Entry) != 1 {
			t.Fatalf("Incorrect entries; expected 1, got '%d'", len(block2.Entry))
		}
		if !bytes.Equal(block2.Entry[0].Record.Payload, []byte("FooBar")) {
			t.Fatalf("Incorrect payload; expected FooBar, got '%s'", block2.Entry[0].Record.Payload)
		}
	})

	t.Run("SingleEntry", func(t *testing.T) {
		cache := test.NewMockCache(t)
		node := node.New(
			test.NewMockAccount(t, test.Alias),
			cache,
			nil,
		)

		r := &bcgo.Record{
			Payload: []byte("FooBar"),
		}
		rh, err := cryptogo.HashProtobuf(r)
		testinggo.AssertNoError(t, err)
		cache.Entries["TEST"] = []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				Record:     r,
				RecordHash: rh,
			},
		}

		channel := test.NewMockChannel(t)
		_, block, err := bcgo.Mine(node, channel, bcgo.THRESHOLD_I, nil)
		testinggo.AssertNoError(t, err)
		if block.Length != 1 {
			t.Fatalf("Incorrect length; expected 1, got '%d'", block.Length)
		}
		if alias := node.Account().Alias(); block.Miner != alias {
			t.Fatalf("Incorrect miner; expected '%s', got '%s'", alias, block.Miner)
		}
		if len(block.Entry) != 1 {
			t.Fatalf("Incorrect entries; expected 1, got '%d'", len(block.Entry))
		}
		if !bytes.Equal(block.Entry[0].Record.Payload, []byte("FooBar")) {
			t.Fatalf("Incorrect payload; expected FooBar, got '%s'", block.Entry[0].Record.Payload)
		}
	})

	t.Run("MultipleEntry", func(t *testing.T) {
		cache := test.NewMockCache(t)
		node := node.New(
			test.NewMockAccount(t, test.Alias),
			cache,
			nil,
		)

		r1 := &bcgo.Record{
			Payload: []byte("Foo"),
		}
		rh1, err := cryptogo.HashProtobuf(r1)
		testinggo.AssertNoError(t, err)
		r2 := &bcgo.Record{
			Payload: []byte("Bar"),
		}
		rh2, err := cryptogo.HashProtobuf(r2)
		testinggo.AssertNoError(t, err)
		cache.Entries["TEST"] = []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				Record:     r1,
				RecordHash: rh1,
			},
			&bcgo.BlockEntry{
				Record:     r2,
				RecordHash: rh2,
			},
		}

		channel := test.NewMockChannel(t)
		_, block, err := bcgo.Mine(node, channel, bcgo.THRESHOLD_I, nil)
		testinggo.AssertNoError(t, err)
		if block.Length != 1 {
			t.Fatalf("Incorrect length; expected 1, got '%d'", block.Length)
		}
		if alias := node.Account().Alias(); block.Miner != alias {
			t.Fatalf("Incorrect miner; expected '%s', got '%s'", alias, block.Miner)
		}
		if len(block.Entry) != 2 {
			t.Fatalf("Incorrect entries; expected 1, got '%d'", len(block.Entry))
		}
		if !bytes.Equal(block.Entry[0].Record.Payload, []byte("Foo")) {
			t.Fatalf("Incorrect payload; expected Foo, got '%s'", block.Entry[0].Record.Payload)
		}
		if !bytes.Equal(block.Entry[1].Record.Payload, []byte("Bar")) {
			t.Fatalf("Incorrect payload; expected Bar, got '%s'", block.Entry[1].Record.Payload)
		}
	})

}
