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
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/testinggo"
	"testing"
)

func AssertNilHead(t *testing.T, channel bcgo.Channel) {
	t.Helper()
	if channel.GetHead() != nil {
		t.Fatal("Expected nil head hash")
	}
}

func makeMockChannel(t *testing.T) *MockChannel {
	t.Helper()
	return &MockChannel{
		Name: "TEST",
	}
}

type MockChannel struct {
	Name       string
	Timestamp  uint64
	HeadHash   []byte
	HeadBlock  *bcgo.Block
	ValidError error
}

func (m *MockChannel) String() string {
	return m.Name
}

func (m *MockChannel) GetName() string {
	return m.Name
}

func (m *MockChannel) GetTimestamp() uint64 {
	return m.Timestamp
}

func (m *MockChannel) SetTimestamp(timestamp uint64) {
	m.Timestamp = timestamp
}

func (m *MockChannel) GetHead() []byte {
	return m.HeadHash
}

func (m *MockChannel) SetHead(hash []byte) {
	m.HeadHash = hash
}

func (m *MockChannel) Validate(cache bcgo.Cache, network bcgo.Network, hash []byte, block *bcgo.Block) error {
	return m.ValidError
}

func TestChannelGetHead(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		channel := makeMockChannel(t)
		AssertNilHead(t, channel)
	})
	t.Run("Cache", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		cache := makeCache(t)
		expected := &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash,
		}
		cache.Head["TEST"] = expected
		head, err := bcgo.GetHeadReference("TEST", cache, nil)
		testinggo.AssertNoError(t, err)
		testinggo.AssertProtobufEqual(t, expected, head)
	})
	t.Run("Network", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		cache := makeCache(t)
		network := makeMockNetwork(t)
		expected := &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash,
		}
		network.Head = expected
		network.Blocks[base64.RawURLEncoding.EncodeToString(hash)] = block
		head, err := bcgo.GetHeadReference("TEST", cache, network)
		testinggo.AssertNoError(t, err)
		testinggo.AssertProtobufEqual(t, expected, head)
	})
	t.Run("Neither", func(t *testing.T) {
		cache := makeCache(t)
		network := makeMockNetwork(t)
		network.HeadError = errors.New("No Head")
		_, err := bcgo.GetHeadReference("TEST", cache, network)
		testinggo.AssertError(t, "No Head", err)
	})
}

func TestChannelUpdate(t *testing.T) {
	t.Run("UpToDate", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		channel := makeMockChannel(t)
		channel.SetHead(hash)
		testinggo.AssertNoError(t, bcgo.Update(channel, nil, nil, hash, block))
	})
	t.Run("WrongHash", func(t *testing.T) {
		block := makeBlock(t, 1234)
		channel := makeMockChannel(t)
		testinggo.AssertError(t, bcgo.ERROR_HASH_INCORRECT, bcgo.Update(channel, nil, nil, []byte("WRONGHASH"), block))
	})
	t.Run("ShortChain", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)

		block2 := &bcgo.Block{
			ChannelName: "TEST",
			Length:      2,
			Previous:    hash,
		}
		hash2 := makeHash(t, block2)
		channel := makeMockChannel(t)
		cache := makeCache(t)
		testinggo.AssertNoError(t, bcgo.Update(channel, cache, nil, hash2, block2))
		testinggo.AssertError(t, fmt.Sprintf(bcgo.ERROR_CHAIN_TOO_SHORT, 1, 2), bcgo.Update(channel, cache, nil, hash, block))
	})
	t.Run("InvalidChain", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		channel := makeMockChannel(t)
		channel.ValidError = errors.New("Foo Bar")

		testinggo.AssertError(t, "Chain invalid: Foo Bar", bcgo.Update(channel, nil, nil, hash, block))
	})
	t.Run("CacheHeadWriteError", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		channel := makeMockChannel(t)
		cache := makeCache(t)
		cache.PutHeadError = errors.New("Put failed")
		testinggo.AssertError(t, "Put failed", bcgo.Update(channel, cache, nil, hash, block))
	})
	t.Run("CacheHeadWrite", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		channel := makeMockChannel(t)
		cache := makeCache(t)
		testinggo.AssertNoError(t, bcgo.Update(channel, cache, nil, hash, block))
		if len(cache.Head) != 1 {
			t.Fatalf("Updated head not put in cache")
		}
		testinggo.AssertHashEqual(t, hash, cache.Head["TEST"].BlockHash)

		channel2 := makeMockChannel(t)
		head, err := bcgo.GetHeadReference(channel2.GetName(), cache, nil)
		testinggo.AssertNoError(t, err)
		testinggo.AssertHashEqual(t, hash, head.BlockHash)
	})
	t.Run("CacheBlockWrite", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		channel := makeMockChannel(t)
		cache := makeCache(t)
		testinggo.AssertNoError(t, bcgo.Update(channel, cache, nil, hash, block))
		if len(cache.Block) != 1 {
			t.Fatalf("Block not put in cache")
		}
		testinggo.AssertProtobufEqual(t, block, cache.Block[base64.RawURLEncoding.EncodeToString(hash)])
	})
}

func TestChannelWriteRecord(t *testing.T) {
	cache := makeCache(t)
	_, err := bcgo.WriteRecord("TEST", cache, &bcgo.Record{
		Payload: []byte("FooBar"),
	})
	testinggo.AssertNoError(t, err)
	if len(cache.Entries) != 1 {
		t.Fatalf("Entry not written to cache")
	}
	got := cache.Entries["TEST"][0].Record.Payload
	if !bytes.Equal(got, []byte("FooBar")) {
		t.Fatalf("Incorrect entry; expected FooBar, got '%s'", got)
	}
}

func TestChannelPull(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		channel := makeMockChannel(t)
		network := makeMockNetwork(t)
		network.HeadError = errors.New("No Head")
		testinggo.AssertError(t, "No Head", bcgo.Pull(channel, nil, network))
		AssertNilHead(t, channel)
	})
	t.Run("LocalRemoteSameChainSameLength", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		channel := makeMockChannel(t)
		channel.SetHead(hash)
		network := makeMockNetwork(t)
		network.Head = &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash,
		}
		testinggo.AssertNoError(t, bcgo.Pull(channel, nil, network))
		// Channel should not change
		testinggo.AssertHashEqual(t, hash, channel.GetHead())
	})
	t.Run("LocalRemoteDifferentChainSameLength", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		cache := makeCache(t)
		cache.Block[base64.RawURLEncoding.EncodeToString(hash)] = block
		channel := makeMockChannel(t)
		channel.SetHead(hash)

		netBlock := makeBlock(t, 2345)
		netHash := makeHash(t, netBlock)
		network := makeMockNetwork(t)
		network.Head = &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   netHash,
		}
		network.Blocks[base64.RawURLEncoding.EncodeToString(netHash)] = netBlock
		testinggo.AssertError(t, fmt.Sprintf(bcgo.ERROR_CHAIN_TOO_SHORT, 1, 1), bcgo.Pull(channel, cache, network))
		// Channel should not change
		testinggo.AssertHashEqual(t, hash, channel.GetHead())
	})
	t.Run("RemoteLongerThanLocal", func(t *testing.T) {
		block1 := makeBlock(t, 1234)
		hash1 := makeHash(t, block1)
		cache := makeCache(t)
		channel := makeMockChannel(t)
		channel.SetHead(hash1)

		block2 := makeLinkedBlock(t, 5678, hash1, block1)
		hash2 := makeHash(t, block2)

		network := makeMockNetwork(t)
		network.Head = &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash2,
		}
		network.Blocks[base64.RawURLEncoding.EncodeToString(hash1)] = block1
		network.Blocks[base64.RawURLEncoding.EncodeToString(hash2)] = block2
		testinggo.AssertNoError(t, bcgo.Pull(channel, cache, network))
		// Channel should update
		testinggo.AssertHashEqual(t, hash2, channel.GetHead())
		// TODO check block2 is in cache
	})
	t.Run("LocalLongerThanRemote", func(t *testing.T) {
		block1 := makeBlock(t, 1234)
		hash1 := makeHash(t, block1)
		block2 := makeLinkedBlock(t, 5678, hash1, block1)
		hash2 := makeHash(t, block2)
		cache := makeCache(t)
		cache.Block[base64.RawURLEncoding.EncodeToString(hash1)] = block1
		cache.Block[base64.RawURLEncoding.EncodeToString(hash2)] = block2
		channel := makeMockChannel(t)
		channel.SetHead(hash2)

		expected := fmt.Sprintf(bcgo.ERROR_CHAIN_TOO_SHORT, 1, 2)

		network := makeMockNetwork(t)
		network.Head = &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash1,
		}
		network.Blocks[base64.RawURLEncoding.EncodeToString(hash1)] = block1
		testinggo.AssertError(t, expected, bcgo.Pull(channel, cache, network))
		// Channel should not change
		testinggo.AssertHashEqual(t, hash2, channel.GetHead())
	})
}

func TestChannelPush(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		channel := makeMockChannel(t)
		cache := makeCache(t)
		cache.Block[base64.RawURLEncoding.EncodeToString(hash)] = block
		channel.SetHead(hash)

		network := makeMockNetwork(t)
		network.HeadError = errors.New("No Head")
		network.BroadcastError = errors.New("Could not Broadcast")
		testinggo.AssertError(t, "Could not Broadcast", bcgo.Push(channel, cache, network))
	})
	t.Run("Success", func(t *testing.T) {
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		channel := makeMockChannel(t)
		cache := makeCache(t)
		cache.Block[base64.RawURLEncoding.EncodeToString(hash)] = block
		channel.SetHead(hash)

		network := makeMockNetwork(t)
		network.Head = &bcgo.Reference{}
		testinggo.AssertNoError(t, bcgo.Push(channel, cache, network))
		testinggo.AssertHashEqual(t, hash, network.BroadcastHash)
		testinggo.AssertProtobufEqual(t, block, network.BroadcastBlock)
	})
}
