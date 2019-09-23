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
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/testinggo"
	"strconv"
	"testing"
)

func makeNode(t *testing.T, a string, key *rsa.PrivateKey, cache bcgo.Cache, network bcgo.Network) *bcgo.Node {
	t.Helper()
	return &bcgo.Node{
		Alias:   a,
		Key:     key,
		Cache:   cache,
		Network: network,
	}
}

func makeMockThresholdChannel(t *testing.T, threshold uint64) *MockThresholdChannel {
	return &MockThresholdChannel{
		Name:      "TEST",
		Threshold: threshold,
	}
}

type MockThresholdChannel struct {
	Name       string
	Threshold  uint64
	Timestamp  uint64
	HeadHash   []byte
	HeadBlock  *bcgo.Block
	ValidError error
}

func (m *MockThresholdChannel) GetName() string {
	return m.Name
}

func (m *MockThresholdChannel) GetTimestamp() uint64 {
	return m.Timestamp
}

func (m *MockThresholdChannel) SetTimestamp(timestamp uint64) {
	m.Timestamp = timestamp
}

func (m *MockThresholdChannel) GetHead() []byte {
	return m.HeadHash
}

func (m *MockThresholdChannel) SetHead(hash []byte) {
	m.HeadHash = hash
}

func (m *MockThresholdChannel) GetThreshold() uint64 {
	return m.Threshold
}

func (m *MockThresholdChannel) String() string {
	return m.Name + " " + strconv.FormatUint(m.Threshold, 10)
}

func (m *MockThresholdChannel) Validate(cache bcgo.Cache, network bcgo.Network, hash []byte, block *bcgo.Block) error {
	return m.ValidError
}

func TestNodeWrite(t *testing.T) {
	t.Run("PayloadTooBig", func(t *testing.T) {
		key := makeKey(t)
		cache := makeCache(t)
		node := makeNode(t, "TESTER", key, cache, nil)
		channel := makeMockThresholdChannel(t, bcgo.THRESHOLD_STANDARD)
		payload := make([]byte, bcgo.MAX_PAYLOAD_SIZE_BYTES+1)
		_, err := node.Write(channel, nil, nil, payload)
		testinggo.AssertError(t, "Payload too large: 10MiB max: 10MiB", err)
		if len(cache.Entries) != 0 {
			t.Fatalf("Entry written to cache")
		}
	})
}

func TestNodeGetLastMinedTimestamp(t *testing.T) {
	t.Run("NoHead", func(t *testing.T) {
		cache := makeCache(t)
		node := makeNode(t, "TESTER", nil, cache, nil)
		channel := makeMockThresholdChannel(t, bcgo.THRESHOLD_STANDARD)

		time, err := node.GetLastMinedTimestamp(channel)
		testinggo.AssertNoError(t, err)
		if time != 0 {
			t.Fatalf("Incorrect timestamp; expected 0 instead got '%d'", time)
		}
	})

	t.Run("LastBlock", func(t *testing.T) {
		cache := makeCache(t)
		node := makeNode(t, "TESTER", nil, cache, nil)

		block := &bcgo.Block{
			Timestamp:   1234,
			ChannelName: "TEST",
			Length:      1,
			Miner:       node.Alias,
		}
		hash := makeHash(t, block)
		cache.Block[base64.RawURLEncoding.EncodeToString(hash)] = block

		channel := makeMockThresholdChannel(t, bcgo.THRESHOLD_STANDARD)
		channel.SetHead(hash)

		time, err := node.GetLastMinedTimestamp(channel)
		testinggo.AssertNoError(t, err)
		if time != 1234 {
			t.Fatalf("Incorrect timestamp; expected 1234 instead got '%d'", time)
		}
	})

	t.Run("FirstBlock", func(t *testing.T) {
		cache := makeCache(t)
		node := makeNode(t, "TESTER", nil, cache, nil)

		block := &bcgo.Block{
			Timestamp:   1234,
			ChannelName: "TEST",
			Length:      1,
			Miner:       node.Alias,
		}
		hash := makeHash(t, block)
		cache.Block[base64.RawURLEncoding.EncodeToString(hash)] = block

		block2 := &bcgo.Block{
			Timestamp:   5678,
			ChannelName: "TEST",
			Length:      2,
			Previous:    hash,
			Miner:       "bob",
		}
		hash2 := makeHash(t, block2)
		cache.Block[base64.RawURLEncoding.EncodeToString(hash2)] = block2

		channel := makeMockThresholdChannel(t, bcgo.THRESHOLD_STANDARD)
		channel.SetHead(hash2)

		time, err := node.GetLastMinedTimestamp(channel)
		testinggo.AssertNoError(t, err)
		if time != 1234 {
			t.Fatalf("Incorrect timestamp; expected 1234 instead got '%d'", time)
		}
	})
}

func TestNodeMine(t *testing.T) {
	t.Run("BlockTooBig", func(t *testing.T) {
		cache := makeCache(t)
		node := makeNode(t, "TESTER", nil, cache, nil)

		r := &bcgo.Record{
			Payload: make([]byte, bcgo.MAX_BLOCK_SIZE_BYTES+1),
		}
		rh, err := bcgo.HashProtobuf(r)
		testinggo.AssertNoError(t, err)
		cache.Entries["TEST"] = []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				Record:     r,
				RecordHash: rh,
			},
		}

		channel := makeMockThresholdChannel(t, bcgo.THRESHOLD_STANDARD)
		_, _, err = node.Mine(channel, nil)
		testinggo.AssertError(t, "Block too large: 2GiB max: 2GiB", err)
	})

	t.Run("ChannelHead", func(t *testing.T) {
		cache := makeCache(t)
		node := makeNode(t, "TESTER", nil, cache, nil)

		block1 := &bcgo.Block{
			Timestamp:   1234,
			ChannelName: "TEST",
			Length:      1,
			Miner:       node.Alias,
		}
		hash1 := makeHash(t, block1)
		cache.Block[base64.RawURLEncoding.EncodeToString(hash1)] = block1

		r := &bcgo.Record{
			Payload: []byte("FooBar"),
		}
		rh, err := bcgo.HashProtobuf(r)
		testinggo.AssertNoError(t, err)
		cache.Entries["TEST"] = []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				Record:     r,
				RecordHash: rh,
			},
		}

		channel := makeMockThresholdChannel(t, bcgo.THRESHOLD_STANDARD)
		channel.SetHead(hash1)
		hash2, block2, err := node.Mine(channel, nil)
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
		if block2.Miner != node.Alias {
			t.Fatalf("Incorrect miner; expected '%s', got '%s'", node.Alias, block2.Miner)
		}
		if len(block2.Entry) != 1 {
			t.Fatalf("Incorrect entries; expected 1, got '%d'", len(block2.Entry))
		}
		if !bytes.Equal(block2.Entry[0].Record.Payload, []byte("FooBar")) {
			t.Fatalf("Incorrect payload; expected FooBar, got '%s'", block2.Entry[0].Record.Payload)
		}
	})

	t.Run("SingleEntry", func(t *testing.T) {
		cache := makeCache(t)
		node := makeNode(t, "TESTER", nil, cache, nil)

		r := &bcgo.Record{
			Payload: []byte("FooBar"),
		}
		rh, err := bcgo.HashProtobuf(r)
		testinggo.AssertNoError(t, err)
		cache.Entries["TEST"] = []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				Record:     r,
				RecordHash: rh,
			},
		}

		channel := makeMockThresholdChannel(t, bcgo.THRESHOLD_STANDARD)
		_, block, err := node.Mine(channel, nil)
		testinggo.AssertNoError(t, err)
		if block.Length != 1 {
			t.Fatalf("Incorrect length; expected 1, got '%d'", block.Length)
		}
		if block.Miner != node.Alias {
			t.Fatalf("Incorrect miner; expected '%s', got '%s'", node.Alias, block.Miner)
		}
		if len(block.Entry) != 1 {
			t.Fatalf("Incorrect entries; expected 1, got '%d'", len(block.Entry))
		}
		if !bytes.Equal(block.Entry[0].Record.Payload, []byte("FooBar")) {
			t.Fatalf("Incorrect payload; expected FooBar, got '%s'", block.Entry[0].Record.Payload)
		}
	})

	t.Run("MultipleEntry", func(t *testing.T) {
		cache := makeCache(t)
		node := makeNode(t, "TESTER", nil, cache, nil)

		r1 := &bcgo.Record{
			Payload: []byte("Foo"),
		}
		rh1, err := bcgo.HashProtobuf(r1)
		testinggo.AssertNoError(t, err)
		r2 := &bcgo.Record{
			Payload: []byte("Bar"),
		}
		rh2, err := bcgo.HashProtobuf(r2)
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

		channel := makeMockThresholdChannel(t, bcgo.THRESHOLD_STANDARD)
		_, block, err := node.Mine(channel, nil)
		testinggo.AssertNoError(t, err)
		if block.Length != 1 {
			t.Fatalf("Incorrect length; expected 1, got '%d'", block.Length)
		}
		if block.Miner != node.Alias {
			t.Fatalf("Incorrect miner; expected '%s', got '%s'", node.Alias, block.Miner)
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
