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

package cache_test

import (
	"aletheiaware.com/bcgo"
	"aletheiaware.com/bcgo/cache"
	"aletheiaware.com/bcgo/test"
	"aletheiaware.com/cryptogo"
	"aletheiaware.com/testinggo"
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
)

const (
	SIZE = 10
)

func TestMemoryBlock(t *testing.T) {
	mc := cache.NewMemory(SIZE)
	block := test.NewMockBlock(t, 1234)
	hash := test.NewHash(t, block)
	_, err := mc.Block(hash)
	testinggo.AssertError(t, fmt.Sprintf(cache.ERROR_BLOCK_NOT_FOUND, base64.RawURLEncoding.EncodeToString(hash)), err)
}

func TestMemoryPutBlock(t *testing.T) {
	mc := cache.NewMemory(SIZE)
	block := test.NewMockBlock(t, 1234)
	hash := test.NewHash(t, block)
	testinggo.AssertNoError(t, mc.PutBlock(hash, block))
	b, err := mc.Block(hash)
	testinggo.AssertNoError(t, err)
	testinggo.AssertProtobufEqual(t, block, b)
}

// func TestMemoryDeleteBlock(t *testing.T) {
// 	mc := cache.NewMemory(SIZE)
// 	block := test.NewMockBlock(t, 1234)
// 	hash := test.NewHash(t, block)
// 	testinggo.AssertNoError(t, mc.PutBlock(hash, block))
// 	testinggo.AssertNoError(t, mc.DeleteBlock(hash))
// 	_, err := mc.Block(hash)
// 	testinggo.AssertError(t, fmt.Sprintf(cache.ERROR_BLOCK_NOT_FOUND, base64.RawURLEncoding.EncodeToString(hash)), err)
// }

func TestMemoryBlockEntries(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		mc := cache.NewMemory(SIZE)
		entries, err := mc.BlockEntries("TEST", 0)
		testinggo.AssertNoError(t, err)
		if len(entries) != 0 {
			t.Fatalf("Incorrect entries; expected 0, got '%d'", len(entries))
		}
	})
	t.Run("Timestamp", func(t *testing.T) {
		mc := cache.NewMemory(SIZE)
		r1 := &bcgo.Record{
			Timestamp: 1234,
			Payload:   []byte("Foo"),
		}
		rh1, err := cryptogo.HashProtobuf(r1)
		testinggo.AssertNoError(t, err)
		testinggo.AssertNoError(t, mc.PutBlockEntry("TEST", &bcgo.BlockEntry{
			Record:     r1,
			RecordHash: rh1,
		}))
		r2 := &bcgo.Record{
			Timestamp: 5678,
			Payload:   []byte("Bar"),
		}
		rh2, err := cryptogo.HashProtobuf(r2)
		testinggo.AssertNoError(t, err)
		testinggo.AssertNoError(t, mc.PutBlockEntry("TEST", &bcgo.BlockEntry{
			Record:     r2,
			RecordHash: rh2,
		}))
		entries, err := mc.BlockEntries("TEST", 3456)
		testinggo.AssertNoError(t, err)
		if len(entries) != 1 {
			t.Fatalf("Incorrect entries; expected 1, got '%d'", len(entries))
		}
		if !bytes.Equal(entries[0].Record.Payload, []byte("Bar")) {
			t.Fatalf("Incorrect entry; expected Bar, got '%s'", entries[0].Record.Payload)
		}
	})
}

func TestMemoryPutBlockEntry(t *testing.T) {
	mc := cache.NewMemory(SIZE)
	r1 := &bcgo.Record{
		Timestamp: 1234,
		Payload:   []byte("Foo"),
	}
	rh1, err := cryptogo.HashProtobuf(r1)
	testinggo.AssertNoError(t, err)
	testinggo.AssertNoError(t, mc.PutBlockEntry("TEST", &bcgo.BlockEntry{
		Record:     r1,
		RecordHash: rh1,
	}))
	r2 := &bcgo.Record{
		Timestamp: 5678,
		Payload:   []byte("Bar"),
	}
	rh2, err := cryptogo.HashProtobuf(r2)
	testinggo.AssertNoError(t, err)
	testinggo.AssertNoError(t, mc.PutBlockEntry("TEST", &bcgo.BlockEntry{
		Record:     r2,
		RecordHash: rh2,
	}))
	entries, err := mc.BlockEntries("TEST", 0)
	testinggo.AssertNoError(t, err)
	if len(entries) != 2 {
		t.Fatalf("Incorrect entries; expected 2, got '%d'", len(entries))
	}
}

func TestMemoryBlockContainingRecord(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		mc := cache.NewMemory(SIZE)
		hash := []byte("FOOBAR")
		_, err := mc.BlockContainingRecord("TEST", hash)
		testinggo.AssertError(t, fmt.Sprintf(cache.ERROR_RECORD_TO_BLOCK_MAPPING_NOT_FOUND, base64.RawURLEncoding.EncodeToString(hash)), err)
	})
	t.Run("Exists", func(t *testing.T) {
		mc := cache.NewMemory(SIZE)
		block := test.NewMockBlock(t, 1234)
		record := test.NewMockRecord(t)
		recordHash := test.NewHash(t, record)
		block.Entry = append(block.Entry, &bcgo.BlockEntry{
			Record:     record,
			RecordHash: recordHash,
		})
		hash := test.NewHash(t, block)
		testinggo.AssertNoError(t, mc.PutBlock(hash, block))
		b, err := mc.BlockContainingRecord("TEST", recordHash)
		testinggo.AssertNoError(t, err)
		testinggo.AssertProtobufEqual(t, block, b)
	})
}

func TestMemoryHead(t *testing.T) {
	mc := cache.NewMemory(SIZE)
	_, err := mc.Head("TEST")
	testinggo.AssertError(t, fmt.Sprintf(cache.ERROR_HEAD_NOT_FOUND, "TEST"), err)
}

func TestMemoryPutHead(t *testing.T) {
	mc := cache.NewMemory(SIZE)
	block := test.NewMockBlock(t, 1234)
	hash := test.NewHash(t, block)
	testinggo.AssertNoError(t, mc.PutHead("TEST", &bcgo.Reference{
		ChannelName: "TEST",
		BlockHash:   hash,
	}))
	ref, err := mc.Head("TEST")
	testinggo.AssertNoError(t, err)
	if ref.ChannelName != "TEST" {
		t.Fatalf("expected error 'TEST', instead got '%s'", ref.ChannelName)
	}
	testinggo.AssertHashEqual(t, hash, ref.BlockHash)
}
