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
	"fmt"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/cryptogo"
	"github.com/AletheiaWareLLC/testinggo"
	"testing"
)

const (
	SIZE = 10
)

func TestMemoryCacheGetBlock(t *testing.T) {
	mc := bcgo.NewMemoryCache(SIZE)
	block := makeBlock(t, 1234)
	hash := makeHash(t, block)
	_, err := mc.GetBlock(hash)
	testinggo.AssertError(t, fmt.Sprintf(bcgo.ERROR_BLOCK_NOT_FOUND, base64.RawURLEncoding.EncodeToString(hash)), err)
}

func TestMemoryCachePutBlock(t *testing.T) {
	mc := bcgo.NewMemoryCache(SIZE)
	block := makeBlock(t, 1234)
	hash := makeHash(t, block)
	testinggo.AssertNoError(t, mc.PutBlock(hash, block))
	b, err := mc.GetBlock(hash)
	testinggo.AssertNoError(t, err)
	testinggo.AssertProtobufEqual(t, block, b)
}

// func TestMemoryCacheDeleteBlock(t *testing.T) {
// 	mc := bcgo.NewMemoryCache(SIZE)
// 	block := makeBlock(t, 1234)
// 	hash := makeHash(t, block)
// 	testinggo.AssertNoError(t, mc.PutBlock(hash, block))
// 	testinggo.AssertNoError(t, mc.DeleteBlock(hash))
// 	_, err := mc.GetBlock(hash)
// 	testinggo.AssertError(t, fmt.Sprintf(bcgo.ERROR_BLOCK_NOT_FOUND, base64.RawURLEncoding.EncodeToString(hash)), err)
// }

func TestMemoryCacheGetBlockEntries(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		mc := bcgo.NewMemoryCache(SIZE)
		entries, err := mc.GetBlockEntries("TEST", 0)
		testinggo.AssertNoError(t, err)
		if len(entries) != 0 {
			t.Fatalf("Incorrect entries; expected 0, got '%d'", len(entries))
		}
	})
	t.Run("Timestamp", func(t *testing.T) {
		mc := bcgo.NewMemoryCache(SIZE)
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
		entries, err := mc.GetBlockEntries("TEST", 3456)
		testinggo.AssertNoError(t, err)
		if len(entries) != 1 {
			t.Fatalf("Incorrect entries; expected 1, got '%d'", len(entries))
		}
		if !bytes.Equal(entries[0].Record.Payload, []byte("Bar")) {
			t.Fatalf("Incorrect entry; expected Bar, got '%s'", entries[0].Record.Payload)
		}
	})
}

func TestMemoryCachePutBlockEntry(t *testing.T) {
	mc := bcgo.NewMemoryCache(SIZE)
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
	entries, err := mc.GetBlockEntries("TEST", 0)
	testinggo.AssertNoError(t, err)
	if len(entries) != 2 {
		t.Fatalf("Incorrect entries; expected 2, got '%d'", len(entries))
	}
}

func TestMemoryCacheGetBlockContainingRecord(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		mc := bcgo.NewMemoryCache(SIZE)
		hash := []byte("FOOBAR")
		_, err := mc.GetBlockContainingRecord("TEST", hash)
		testinggo.AssertError(t, fmt.Sprintf(bcgo.ERROR_BLOCK_NOT_FOUND, base64.RawURLEncoding.EncodeToString(hash)), err)
	})
	t.Run("Exists", func(t *testing.T) {
		mc := bcgo.NewMemoryCache(SIZE)
		block := makeBlock(t, 1234)
		record := makeRecord(t)
		recordHash := makeHash(t, record)
		block.Entry = append(block.Entry, &bcgo.BlockEntry{
			Record:     record,
			RecordHash: recordHash,
		})
		hash := makeHash(t, block)
		testinggo.AssertNoError(t, mc.PutBlock(hash, block))
		b, err := mc.GetBlockContainingRecord("TEST", recordHash)
		testinggo.AssertNoError(t, err)
		testinggo.AssertProtobufEqual(t, block, b)
	})
}

func TestMemoryCacheGetHead(t *testing.T) {
	mc := bcgo.NewMemoryCache(SIZE)
	_, err := mc.GetHead("TEST")
	testinggo.AssertError(t, fmt.Sprintf(bcgo.ERROR_HEAD_NOT_FOUND, "TEST"), err)
}

func TestMemoryCachePutHead(t *testing.T) {
	mc := bcgo.NewMemoryCache(SIZE)
	block := makeBlock(t, 1234)
	hash := makeHash(t, block)
	testinggo.AssertNoError(t, mc.PutHead("TEST", &bcgo.Reference{
		ChannelName: "TEST",
		BlockHash:   hash,
	}))
	ref, err := mc.GetHead("TEST")
	testinggo.AssertNoError(t, err)
	if ref.ChannelName != "TEST" {
		t.Fatalf("expected error 'TEST', instead got '%s'", ref.ChannelName)
	}
	testinggo.AssertHashEqual(t, hash, ref.BlockHash)
}
