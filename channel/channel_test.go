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
	"aletheiaware.com/testinggo"
	"bytes"
	"encoding/base64"
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestChannelHead(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		channel := channel.New("TEST")
		test.AssertNilHead(t, channel)
	})
	t.Run("Cache", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		cache := test.NewMockCache(t)
		expected := &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash,
		}
		cache.Heads["TEST"] = expected
		head, err := bcgo.LoadHead("TEST", cache, nil)
		testinggo.AssertNoError(t, err)
		testinggo.AssertProtobufEqual(t, expected, head)
	})
	t.Run("Network", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		cache := test.NewMockCache(t)
		network := test.NewMockNetwork(t)
		expected := &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash,
		}
		network.Heads["TEST"] = expected
		network.Blocks[base64.RawURLEncoding.EncodeToString(hash)] = block
		head, err := bcgo.LoadHead("TEST", cache, network)
		testinggo.AssertNoError(t, err)
		testinggo.AssertProtobufEqual(t, expected, head)
	})
	t.Run("Neither", func(t *testing.T) {
		cache := test.NewMockCache(t)
		network := test.NewMockNetwork(t)
		network.HeadError = errors.New("No Such Head")
		_, err := bcgo.LoadHead("TEST", cache, network)
		testinggo.AssertError(t, "No Such Head", err)
	})
}

func TestChannelUpdate(t *testing.T) {
	t.Run("UpToDate", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		channel := channel.New("TEST")
		channel.Set(1234, hash)
		testinggo.AssertNoError(t, channel.Update(nil, nil, hash, block))
	})
	t.Run("WrongHash", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		channel := channel.New("TEST")
		testinggo.AssertError(t, bcgo.ErrBlockHashIncorrect{}.Error(), channel.Update(nil, nil, []byte("WRONGHASH"), block))
	})
	t.Run("ShortChain", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)

		block2 := &bcgo.Block{
			ChannelName: "TEST",
			Length:      2,
			Previous:    hash,
		}
		hash2 := test.NewHash(t, block2)
		channel := channel.New("TEST")
		cache := test.NewMockCache(t)
		testinggo.AssertNoError(t, channel.Update(cache, nil, hash2, block2))
		testinggo.AssertError(t, bcgo.ErrChainTooShort{LengthA: 2, LengthB: 1}.Error(), channel.Update(cache, nil, hash, block))
	})
	t.Run("InvalidChain", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		channel := channel.New("TEST")
		channel.AddValidator(test.NewMockValidator(t, errors.New("Foo Bar")))

		testinggo.AssertError(t, "Chain invalid: Foo Bar", channel.Update(nil, nil, hash, block))
	})
	t.Run("CacheHeadWriteError", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		channel := channel.New("TEST")
		cache := test.NewMockCache(t)
		cache.PutHeadError = errors.New("Put failed")
		testinggo.AssertError(t, "Put failed", channel.Update(cache, nil, hash, block))
	})
	t.Run("CacheHeadWrite", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		channel1 := channel.New("TEST")
		cache := test.NewMockCache(t)
		testinggo.AssertNoError(t, channel1.Update(cache, nil, hash, block))
		if len(cache.Heads) != 1 {
			t.Fatalf("Updated head not put in cache")
		}
		testinggo.AssertHashEqual(t, hash, cache.Heads["TEST"].BlockHash)

		channel2 := channel.New("TEST")
		head, err := bcgo.LoadHead(channel2.Name(), cache, nil)
		testinggo.AssertNoError(t, err)
		testinggo.AssertHashEqual(t, hash, head.BlockHash)
	})
	t.Run("CacheBlockWrite", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		channel := channel.New("TEST")
		cache := test.NewMockCache(t)
		testinggo.AssertNoError(t, channel.Update(cache, nil, hash, block))
		if len(cache.Blocks) != 1 {
			t.Fatalf("Block not put in cache")
		}
		testinggo.AssertProtobufEqual(t, block, cache.Blocks[base64.RawURLEncoding.EncodeToString(hash)])
	})
}

func TestChannelWriteRecord(t *testing.T) {
	cache := test.NewMockCache(t)
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
		channel := channel.New("TEST")
		network := test.NewMockNetwork(t)
		network.HeadError = errors.New("No Such Head")
		testinggo.AssertError(t, "No Such Head", channel.Pull(nil, network))
		test.AssertNilHead(t, channel)
	})
	t.Run("LocalRemoteSameChainSameLength", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		channel := channel.New("TEST")
		channel.Set(1234, hash)
		network := test.NewMockNetwork(t)
		network.Heads["TEST"] = &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash,
		}
		testinggo.AssertNoError(t, channel.Pull(nil, network))
		// Channel should not change
		testinggo.AssertHashEqual(t, hash, channel.Head())
	})
	t.Run("LocalRemoteDifferentChainSameLength", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		cache := test.NewMockCache(t)
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash)] = block
		channel := channel.New("TEST")
		channel.Set(1234, hash)

		netBlock := test.NewMockBlock(t, 2345)
		netHash := test.NewHash(t, netBlock)
		network := test.NewMockNetwork(t)
		network.Heads["TEST"] = &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   netHash,
		}
		network.Blocks[base64.RawURLEncoding.EncodeToString(netHash)] = netBlock
		testinggo.AssertError(t, bcgo.ErrChainTooShort{LengthA: 1, LengthB: 1}.Error(), channel.Pull(cache, network))
		// Channel should not change
		testinggo.AssertHashEqual(t, hash, channel.Head())
	})
	t.Run("RemoteLongerThanLocal", func(t *testing.T) {
		block1 := test.NewMockBlock(t, 1234)
		hash1 := test.NewHash(t, block1)
		cache := test.NewMockCache(t)
		channel := channel.New("TEST")
		channel.Set(1234, hash1)

		block2 := test.NewMockLinkedBlock(t, 5678, hash1, block1)
		hash2 := test.NewHash(t, block2)

		network := test.NewMockNetwork(t)
		network.Heads["TEST"] = &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash2,
		}
		network.Blocks[base64.RawURLEncoding.EncodeToString(hash1)] = block1
		network.Blocks[base64.RawURLEncoding.EncodeToString(hash2)] = block2
		testinggo.AssertNoError(t, channel.Pull(cache, network))
		// Channel should update
		testinggo.AssertHashEqual(t, hash2, channel.Head())
		if _, ok := cache.Blocks[base64.RawURLEncoding.EncodeToString(hash2)]; !ok {
			t.Errorf("Expected cache to hold block2")
		}
	})
	t.Run("LocalLongerThanRemote", func(t *testing.T) {
		block1 := test.NewMockBlock(t, 1234)
		hash1 := test.NewHash(t, block1)
		block2 := test.NewMockLinkedBlock(t, 5678, hash1, block1)
		hash2 := test.NewHash(t, block2)
		cache := test.NewMockCache(t)
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash1)] = block1
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash2)] = block2
		channel := channel.New("TEST")
		channel.Set(5678, hash2)

		expected := bcgo.ErrChainTooShort{LengthA: 2, LengthB: 1}.Error()

		network := test.NewMockNetwork(t)
		network.Heads["TEST"] = &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash1,
		}
		network.Blocks[base64.RawURLEncoding.EncodeToString(hash1)] = block1
		testinggo.AssertError(t, expected, channel.Pull(cache, network))
		// Channel should not change
		testinggo.AssertHashEqual(t, hash2, channel.Head())
	})
}

func TestChannelPush(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		channel := channel.New("TEST")
		cache := test.NewMockCache(t)
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash)] = block
		channel.Set(1234, hash)

		network := test.NewMockNetwork(t)
		network.HeadError = errors.New("No Such Head")
		network.BroadcastError = errors.New("Could not Broadcast")
		testinggo.AssertError(t, "Could not Broadcast", channel.Push(cache, network))
	})
	t.Run("Success", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		channel := channel.New("TEST")
		cache := test.NewMockCache(t)
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash)] = block
		channel.Set(1234, hash)

		network := test.NewMockNetwork(t)
		network.Heads["TEST"] = &bcgo.Reference{}
		testinggo.AssertNoError(t, channel.Push(cache, network))
		testinggo.AssertHashEqual(t, hash, network.BroadcastHash)
		testinggo.AssertProtobufEqual(t, block, network.BroadcastBlock)
	})
}

func TestChannelRefresh(t *testing.T) {
	t.Run("CacheError", func(t *testing.T) {
		cache := test.NewMockCache(t)
		channel := channel.New("TEST")
		testinggo.AssertError(t, "No Such Head", channel.Refresh(cache, nil))
		test.AssertNilHead(t, channel)
	})
	t.Run("NetworkError", func(t *testing.T) {
		cache := test.NewMockCache(t)
		network := test.NewMockNetwork(t)
		network.HeadError = errors.New("No Such Head")
		channel := channel.New("TEST")
		testinggo.AssertError(t, "No Such Head", channel.Refresh(cache, network))
		test.AssertNilHead(t, channel)
	})
	t.Run("RemoteEqualToLocal", func(t *testing.T) {
		block := test.NewMockBlock(t, 1234)
		hash := test.NewHash(t, block)
		cache := test.NewMockCache(t)
		ref := &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash,
		}
		cache.Heads["TEST"] = ref
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash)] = block
		network := test.NewMockNetwork(t)
		network.Heads["TEST"] = ref
		network.Blocks[base64.RawURLEncoding.EncodeToString(hash)] = block
		channel := channel.New("TEST")
		channel.Set(1234, hash)
		testinggo.AssertNoError(t, channel.Refresh(cache, network))
		// Channel should not change
		testinggo.AssertHashEqual(t, hash, channel.Head())
	})
	t.Run("RemoteLongerThanLocal", func(t *testing.T) {
		block1 := test.NewMockBlock(t, 1234)
		hash1 := test.NewHash(t, block1)
		block2 := test.NewMockLinkedBlock(t, 5678, hash1, block1)
		hash2 := test.NewHash(t, block2)
		cache := test.NewMockCache(t)
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash1)] = block1
		channel := channel.New("TEST")
		channel.Set(1234, hash1)
		network := test.NewMockNetwork(t)
		network.Heads["TEST"] = &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash2,
		}
		network.Blocks[base64.RawURLEncoding.EncodeToString(hash1)] = block1
		network.Blocks[base64.RawURLEncoding.EncodeToString(hash2)] = block2
		testinggo.AssertNoError(t, channel.Refresh(cache, network))
		// Channel should change
		testinggo.AssertHashEqual(t, hash2, channel.Head())
		// Network should not receive broadcast
		assert.Nil(t, network.BroadcastHash)
	})
	t.Run("LocalLongerThanRemote", func(t *testing.T) {
		block1 := test.NewMockBlock(t, 1234)
		hash1 := test.NewHash(t, block1)
		block2 := test.NewMockLinkedBlock(t, 5678, hash1, block1)
		hash2 := test.NewHash(t, block2)
		cache := test.NewMockCache(t)
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash1)] = block1
		cache.Blocks[base64.RawURLEncoding.EncodeToString(hash2)] = block2
		channel := channel.New("TEST")
		channel.Set(5678, hash2)
		network := test.NewMockNetwork(t)
		network.Heads["TEST"] = &bcgo.Reference{
			ChannelName: "TEST",
			BlockHash:   hash1,
		}
		network.Blocks[base64.RawURLEncoding.EncodeToString(hash1)] = block1
		testinggo.AssertNoError(t, channel.Refresh(cache, network))
		// Channel should not change
		testinggo.AssertHashEqual(t, hash2, channel.Head())
		// Network should receive broadcast
		testinggo.AssertHashEqual(t, hash2, network.BroadcastHash)
	})
}
