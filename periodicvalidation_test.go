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
	"aletheiaware.com/bcgo"
	"aletheiaware.com/testinggo"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/golang/protobuf/proto"
	"testing"
	"time"
)

func TestPeriodicValidator_FillChannelSet(t *testing.T) {
	validator := &bcgo.PeriodicValidator{
		Channel: &bcgo.Channel{
			Name: "PV",
		},
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Error("Could not generate key:", err)
	}
	cache := makeMockCache(t)
	node := makeNode(t, "TESTER", key, cache, nil)
	channel := makeMockChannel(t)
	node.AddChannel(channel)
	block := makeBlock(t, 1234)
	hash := makeHash(t, block)
	testinggo.AssertNoError(t, channel.Update(cache, nil, hash, block))
	entries, err := bcgo.CreateValidationEntries(3456, node, map[string]bool{
		channel.Name: true,
	})
	testinggo.AssertNoError(t, err)
	b := bcgo.CreateValidationBlock(5678, validator.Channel.Name, node.Alias, nil, nil, entries)
	h := makeHash(t, b)
	testinggo.AssertNoError(t, validator.Channel.Update(cache, nil, h, b))
	set := make(map[string]bool)
	testinggo.AssertNoError(t, validator.FillChannelSet(set, cache, nil))
	if len(set) != 1 {
		t.Fatal(fmt.Sprintf("Incorrect set size; expected '%d', got '%d'", 1, len(set)))
	}
	mark, ok := set[channel.Name]
	if !ok || !mark {
		t.Fatal(fmt.Sprintf("Missing channel name; '%s'", channel.Name))
	}
}

func TestPeriodicValidator_Validate(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		validator := &bcgo.PeriodicValidator{
			Channel: &bcgo.Channel{
				Name: "PV",
			},
		}
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Error("Could not generate key:", err)
		}
		cache := makeMockCache(t)
		node := makeNode(t, "TESTER", key, cache, nil)
		channel := makeMockChannel(t)
		channel.AddValidator(validator)
		node.AddChannel(channel)
		block := makeBlock(t, 1234)
		hash := makeHash(t, block)
		testinggo.AssertNoError(t, channel.Update(cache, nil, hash, block))
	})
	t.Run("Valid", func(t *testing.T) {
		// Chain of A, Validated
		// Update to Chain of A,B should be valid
		validator := &bcgo.PeriodicValidator{
			Channel: &bcgo.Channel{
				Name: "PV",
			},
		}
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Error("Could not generate key:", err)
		}
		cache := makeMockCache(t)
		node := makeNode(t, "TESTER", key, cache, nil)
		channel := makeMockChannel(t)
		channel.AddValidator(validator)
		node.AddChannel(channel)
		blockA := makeBlock(t, 1234)
		hashA := makeHash(t, blockA)
		testinggo.AssertNoError(t, channel.Update(cache, nil, hashA, blockA))
		entries, err := bcgo.CreateValidationEntries(3456, node, map[string]bool{
			channel.Name: true,
		})
		testinggo.AssertNoError(t, err)
		b := bcgo.CreateValidationBlock(5678, validator.Channel.Name, node.Alias, nil, nil, entries)
		h := makeHash(t, b)
		testinggo.AssertNoError(t, validator.Channel.Update(cache, nil, h, b))

		blockB := makeLinkedBlock(t, 5678, hashA, blockA)
		hashB := makeHash(t, blockB)
		testinggo.AssertNoError(t, channel.Update(cache, nil, hashB, blockB))
	})
	t.Run("Invalid", func(t *testing.T) {
		// Chain of A, Validated
		// Update to Chain of B,C should be invalid (missing A)
		validator := &bcgo.PeriodicValidator{
			Channel: &bcgo.Channel{
				Name: "PV",
			},
		}
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Error("Could not generate key:", err)
		}
		cache := makeMockCache(t)
		node := makeNode(t, "TESTER", key, cache, nil)
		channel := makeMockChannel(t)
		channel.AddValidator(validator)
		node.AddChannel(channel)
		blockA := makeBlock(t, 1234)
		hashA := makeHash(t, blockA)
		testinggo.AssertNoError(t, channel.Update(cache, nil, hashA, blockA))
		entries, err := bcgo.CreateValidationEntries(3456, node, map[string]bool{
			channel.Name: true,
		})
		testinggo.AssertNoError(t, err)
		b := bcgo.CreateValidationBlock(5678, validator.Channel.Name, node.Alias, nil, nil, entries)
		h := makeHash(t, b)
		testinggo.AssertNoError(t, validator.Channel.Update(cache, nil, h, b))
		blockB := makeBlock(t, 3456)
		hashB := makeHash(t, blockB)
		cache.PutBlock(hashB, blockB)
		blockC := makeLinkedBlock(t, 5678, hashB, blockB)
		hashC := makeHash(t, blockC)
		err = channel.Update(cache, nil, hashC, blockC)
		testinggo.AssertError(t, fmt.Sprintf("Chain invalid: PV Missing Validated Block TEST %s", base64.RawURLEncoding.EncodeToString(hashA)), err)
	})
}

func TestPeriodicValidator_Validate_ForkResolution(t *testing.T) {
	// Miners Alice and Bob both mine new blocks onto Chain A and Validator PV
	aliceKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Error("Could not generate Alice Key:", err)
	}
	aliceCache := makeMockCache(t)
	aliceNode := makeNode(t, "Alice", aliceKey, aliceCache, nil)
	aliceValidator := bcgo.NewPeriodicValidator(aliceNode, &bcgo.Channel{
		Name: "PV",
	}, 0, nil, time.Second)
	aliceValidator.Channel.AddValidator(aliceValidator)
	aliceChannel := makeMockChannel(t)
	aliceChannel.AddValidator(aliceValidator)
	aliceNode.AddChannel(aliceChannel)

	bobKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Error("Could not generate Bob Key:", err)
	}
	bobCache := makeMockCache(t)
	bobNode := makeNode(t, "Bob", bobKey, bobCache, nil)
	bobValidator := bcgo.NewPeriodicValidator(bobNode, &bcgo.Channel{
		Name: "PV",
	}, 0, nil, time.Second)
	bobValidator.Channel.AddValidator(bobValidator)
	bobChannel := makeMockChannel(t)
	bobChannel.AddValidator(bobValidator)
	bobNode.AddChannel(bobChannel)

	// Initial block
	block1 := makeBlock(t, 1234)
	hash1 := makeHash(t, block1)
	testinggo.AssertNoError(t, aliceChannel.Update(aliceCache, nil, hash1, block1))
	testinggo.AssertNoError(t, bobChannel.Update(bobCache, nil, hash1, block1))
	entries, err := bcgo.CreateValidationEntries(2345, aliceNode, map[string]bool{
		aliceChannel.Name: true,
	})
	testinggo.AssertNoError(t, err)
	blockV1 := bcgo.CreateValidationBlock(3456, aliceValidator.Channel.Name, aliceNode.Alias, nil, nil, entries)
	hashV1 := makeHash(t, blockV1)
	testinggo.AssertNoError(t, aliceValidator.Channel.Update(aliceCache, nil, hashV1, blockV1))
	testinggo.AssertNoError(t, bobValidator.Channel.Update(bobCache, nil, hashV1, blockV1))

	// Fork 1 - Alice mines Channel
	block2Fork1 := makeLinkedBlock(t, 4567, hash1, block1)
	block2Fork1.Nonce = 1 // Make nonces different, so hash is different
	hash2Fork1 := makeHash(t, block2Fork1)
	testinggo.AssertNoError(t, aliceChannel.Update(aliceCache, nil, hash2Fork1, block2Fork1))
	bobCache.PutBlock(hash2Fork1, block2Fork1)

	// Fork 2 - Bob mines Channel
	block2Fork2 := makeLinkedBlock(t, 4567, hash1, block1)
	block2Fork2.Nonce = 2 // Make nonces different, so hash is different
	hash2Fork2 := makeHash(t, block2Fork2)
	testinggo.AssertNoError(t, bobChannel.Update(bobCache, nil, hash2Fork2, block2Fork2))
	aliceCache.PutBlock(hash2Fork2, block2Fork2)

	// Conflict
	// Alice can't update Bob
	testinggo.AssertError(t, "Chain too short to replace current head: 2 vs 2", bobChannel.Update(bobCache, nil, hash2Fork1, block2Fork1))
	// Bob can't update Alice
	testinggo.AssertError(t, "Chain too short to replace current head: 2 vs 2", aliceChannel.Update(aliceCache, nil, hash2Fork2, block2Fork2))

	// Fork 1 - Alice mines Validator
	entries2Fork1, err := bcgo.CreateValidationEntries(5678, aliceNode, map[string]bool{
		aliceChannel.Name: true,
	})
	testinggo.AssertNoError(t, err)
	blockV2Fork1 := bcgo.CreateValidationBlock(6789, aliceValidator.Channel.Name, aliceNode.Alias, hashV1, blockV1, entries2Fork1)
	hashV2Fork1 := makeHash(t, blockV2Fork1)
	testinggo.AssertNoError(t, aliceValidator.Channel.Update(aliceCache, nil, hashV2Fork1, blockV2Fork1))
	bobCache.PutBlock(hashV2Fork1, blockV2Fork1)

	// Fork 2 - Bob mines Validator
	entries2Fork2, err := bcgo.CreateValidationEntries(5678, bobNode, map[string]bool{
		bobChannel.Name: true,
	})
	testinggo.AssertNoError(t, err)
	blockV2Fork2 := bcgo.CreateValidationBlock(6789, bobValidator.Channel.Name, bobNode.Alias, hashV1, blockV1, entries2Fork2)
	hashV2Fork2 := makeHash(t, blockV2Fork2)
	testinggo.AssertNoError(t, bobValidator.Channel.Update(bobCache, nil, hashV2Fork2, blockV2Fork2))
	aliceCache.PutBlock(hashV2Fork2, blockV2Fork2)

	// Conflict
	// Alice can't update Bob
	testinggo.AssertError(t, "Chain too short to replace current head: 2 vs 2", bobValidator.Channel.Update(bobCache, nil, hashV2Fork1, blockV2Fork1))
	// Bob can't update Alice
	testinggo.AssertError(t, "Chain too short to replace current head: 2 vs 2", aliceValidator.Channel.Update(aliceCache, nil, hashV2Fork2, blockV2Fork2))

	// Fork 1 - Alice mines Channel
	block3Fork1 := makeLinkedBlock(t, 7890, hash2Fork1, block2Fork1)
	hash3Fork1 := makeHash(t, block3Fork1)
	testinggo.AssertNoError(t, aliceChannel.Update(aliceCache, nil, hash3Fork1, block3Fork1))
	bobCache.PutBlock(hash3Fork1, block3Fork1)

	// Fork 2 - Bob mines Channel
	block3Fork2 := makeLinkedBlock(t, 7890, hash2Fork2, block2Fork2)
	hash3Fork2 := makeHash(t, block3Fork2)
	testinggo.AssertNoError(t, bobChannel.Update(bobCache, nil, hash3Fork2, block3Fork2))
	aliceCache.PutBlock(hash3Fork2, block3Fork2)

	// Conflict
	// Alice can't update Bob
	testinggo.AssertError(t, fmt.Sprintf("Chain invalid: PV Missing Validated Block TEST %s", base64.RawURLEncoding.EncodeToString(hash2Fork2)), bobChannel.Update(bobCache, nil, hash3Fork1, block3Fork1))
	// Bob can't update Alice
	testinggo.AssertError(t, fmt.Sprintf("Chain invalid: PV Missing Validated Block TEST %s", base64.RawURLEncoding.EncodeToString(hash2Fork1)), aliceChannel.Update(aliceCache, nil, hash3Fork2, block3Fork2))

	// Whichever fork mines the next Validator should win, in this case Alice
	// Fork 1 - Alice mines Validator
	entries3Fork1, err := bcgo.CreateValidationEntries(8901, aliceNode, map[string]bool{
		aliceChannel.Name: true,
	})
	testinggo.AssertNoError(t, err)
	blockV3Fork1 := bcgo.CreateValidationBlock(9012, aliceValidator.Channel.Name, aliceNode.Alias, hashV2Fork1, blockV2Fork1, entries3Fork1)
	hashV3Fork1 := makeHash(t, blockV3Fork1)
	testinggo.AssertNoError(t, aliceValidator.Channel.Update(aliceCache, nil, hashV3Fork1, blockV3Fork1))

	// Should be able to update Bob as Validator is longer
	testinggo.AssertNoError(t, bobValidator.Channel.Update(bobCache, nil, hashV3Fork1, blockV3Fork1))

	// Check Bob Channel is also updated
	testinggo.AssertHashEqual(t, hash3Fork1, bobChannel.Head)
}

func TestCreateValidationBlock(t *testing.T) {
	block := makeBlock(t, 1234)
	hash := makeHash(t, block)
	actual := bcgo.CreateValidationBlock(5678, "PV", "TESTER", hash, block, nil)
	if actual.Timestamp != 5678 {
		t.Fatal("Incorrect timestamp")
	}
	if actual.ChannelName != "PV" {
		t.Fatal("Incorrect channel name")
	}
	if actual.Length != 2 {
		t.Fatal("Incorrect length")
	}
	if actual.Miner != "TESTER" {
		t.Fatal("Incorrect miner")
	}
}

func AssertEntry(t *testing.T, timestamp uint64, channel string, hash []byte, entry *bcgo.BlockEntry) {
	t.Helper()
	actual := &bcgo.Reference{}
	err := proto.Unmarshal(entry.Record.Payload, actual)
	testinggo.AssertNoError(t, err)
	if actual.Timestamp != timestamp {
		t.Fatal("Incorrect timestamp")
	}
	if actual.ChannelName != channel {
		t.Fatal("Incorrect channel name")
	}
	testinggo.AssertHashEqual(t, hash, actual.BlockHash)
}

func TestCreateValidationEntries(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Error("Could not generate key:", err)
	}
	cache := makeMockCache(t)
	node := makeNode(t, "TESTER", key, cache, nil)
	channel := makeMockChannel(t)
	node.AddChannel(channel)
	block1 := makeBlock(t, 1234)
	hash1 := makeHash(t, block1)
	channel.Update(cache, nil, hash1, block1)
	block2 := makeLinkedBlock(t, 5678, hash1, block1)
	hash2 := makeHash(t, block2)
	channel.Update(cache, nil, hash2, block2)
	t.Run("Before", func(t *testing.T) {
		entries, err := bcgo.CreateValidationEntries(0123, node, map[string]bool{
			channel.Name: true,
		})
		testinggo.AssertNoError(t, err)
		if len(entries) != 0 {
			t.Fatalf("Incorrect number of entries; expected '%d', got '%d'", 0, len(entries))
		}
	})
	t.Run("Middle", func(t *testing.T) {
		entries, err := bcgo.CreateValidationEntries(3456, node, map[string]bool{
			channel.Name: true,
		})
		testinggo.AssertNoError(t, err)
		if len(entries) != 1 {
			t.Fatalf("Incorrect number of entries; expected '%d', got '%d'", 1, len(entries))
		}
		AssertEntry(t, 1234, "TEST", hash1, entries[0])
	})
	t.Run("After", func(t *testing.T) {
		entries, err := bcgo.CreateValidationEntries(9012, node, map[string]bool{
			channel.Name: true,
		})
		testinggo.AssertNoError(t, err)
		if len(entries) != 1 {
			t.Fatalf("Incorrect number of entries; expected '%d', got '%d'", 1, len(entries))
		}
		AssertEntry(t, 5678, "TEST", hash2, entries[0])
	})
}

func TestCreateValidationEntry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Error("Could not generate key:", err)
	}
	cache := makeMockCache(t)
	node := makeNode(t, "TESTER", key, cache, nil)
	channel := makeMockChannel(t)
	node.AddChannel(channel)
	block := makeBlock(t, 1234)
	hash := makeHash(t, block)
	channel.Update(cache, nil, hash, block)
	entry, err := bcgo.CreateValidationEntry(0, node, channel.Name, channel.Timestamp, hash)
	testinggo.AssertNoError(t, err)
	AssertEntry(t, 1234, "TEST", hash, entry)
}
