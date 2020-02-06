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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/testinggo"
	"github.com/golang/protobuf/proto"
	"testing"
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
	channel.Update(cache, nil, hash, block)
	entries, err := bcgo.CreateValidationEntries(3456, node)
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
		channel.Update(cache, nil, hashA, blockA)
		entries, err := bcgo.CreateValidationEntries(3456, node)
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
		channel.Update(cache, nil, hashA, blockA)
		entries, err := bcgo.CreateValidationEntries(3456, node)
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
		testinggo.AssertError(t, fmt.Sprintf("Chain invalid: Missing Validated Block %s", base64.RawURLEncoding.EncodeToString(hashA)), err)
	})
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
		entries, err := bcgo.CreateValidationEntries(0123, node)
		testinggo.AssertNoError(t, err)
		if len(entries) != 0 {
			t.Fatalf("Incorrect number of entries; expected '%d', got '%d'", 0, len(entries))
		}
	})
	t.Run("Middle", func(t *testing.T) {
		entries, err := bcgo.CreateValidationEntries(3456, node)
		testinggo.AssertNoError(t, err)
		if len(entries) != 1 {
			t.Fatalf("Incorrect number of entries; expected '%d', got '%d'", 1, len(entries))
		}
		AssertEntry(t, 1234, "TEST", hash1, entries[0])
	})
	t.Run("After", func(t *testing.T) {
		entries, err := bcgo.CreateValidationEntries(9012, node)
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
