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
	"github.com/golang/protobuf/proto"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func makeCacheDir(t *testing.T) string {
	t.Helper()
	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Fatalf("Could not create temp cache dir: '%s'", err)
	}
	return dir
}

func unmakeCacheDir(t *testing.T, cacheDir string) {
	t.Helper()
	os.RemoveAll(cacheDir)
}

func TestFileSystemBlock(t *testing.T) {
	cacheDir := makeCacheDir(t)
	defer unmakeCacheDir(t, cacheDir)
	fc, err := cache.NewFileSystem(cacheDir)
	testinggo.AssertNoError(t, err)
	block := test.NewMockBlock(t, 1234)
	hash := test.NewHash(t, block)
	_, err = fc.Block(hash)
	testinggo.AssertMatchesError(t, "^.*: no such file or directory", err)
}

func TestFileSystemPutBlock(t *testing.T) {
	cacheDir := makeCacheDir(t)
	defer unmakeCacheDir(t, cacheDir)
	fc, err := cache.NewFileSystem(cacheDir)
	testinggo.AssertNoError(t, err)
	block := test.NewMockBlock(t, 1234)
	hash := test.NewHash(t, block)
	testinggo.AssertNoError(t, fc.PutBlock(hash, block))
	b, err := fc.Block(hash)
	testinggo.AssertNoError(t, err)
	testinggo.AssertProtobufEqual(t, block, b)
}

// func TestFileSystemDeleteBlock(t *testing.T) {
// 	cacheDir := makeCacheDir(t)
// 	defer unmakeCacheDir(t, cacheDir)
// 	fc, err := cache.NewFileSystem(cacheDir)
// 	testinggo.AssertNoError(t, err)
// 	block := test.NewMockBlock(t, 1234)
// 	hash := test.NewHash(t, block)
// 	testinggo.AssertNoError(t, fc.PutBlock(hash, block))
// 	testinggo.AssertNoError(t, fc.DeleteBlock(hash))
// 	_, err = fc.Block(hash)
// 	testinggo.AssertMatchesError(t, "^.*: no such file or directory", err)
// }

func TestFileSystemBlockEntries(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		cacheDir := makeCacheDir(t)
		defer unmakeCacheDir(t, cacheDir)
		fc, err := cache.NewFileSystem(cacheDir)
		testinggo.AssertNoError(t, err)
		_, err = fc.BlockEntries("TEST", 0)
		testinggo.AssertMatchesError(t, "^.*: no such file or directory", err)
	})
	t.Run("Timestamp", func(t *testing.T) {
		cacheDir := makeCacheDir(t)
		defer unmakeCacheDir(t, cacheDir)
		fc, err := cache.NewFileSystem(cacheDir)
		testinggo.AssertNoError(t, err)
		r1 := &bcgo.Record{
			Timestamp: 1234,
			Payload:   []byte("Foo"),
		}
		rh1, err := cryptogo.HashProtobuf(r1)
		testinggo.AssertNoError(t, err)
		testinggo.AssertNoError(t, fc.PutBlockEntry("TEST", &bcgo.BlockEntry{
			Record:     r1,
			RecordHash: rh1,
		}))
		r2 := &bcgo.Record{
			Timestamp: 5678,
			Payload:   []byte("Bar"),
		}
		rh2, err := cryptogo.HashProtobuf(r2)
		testinggo.AssertNoError(t, err)
		testinggo.AssertNoError(t, fc.PutBlockEntry("TEST", &bcgo.BlockEntry{
			Record:     r2,
			RecordHash: rh2,
		}))
		entries, err := fc.BlockEntries("TEST", 3456)
		testinggo.AssertNoError(t, err)
		if len(entries) != 1 {
			t.Fatalf("Incorrect entries; expected 1, got '%d'", len(entries))
		}
		if !bytes.Equal(entries[0].Record.Payload, []byte("Bar")) {
			t.Fatalf("Incorrect entry; expected Bar, got '%s'", entries[0].Record.Payload)
		}
	})
}

func TestFileSystemPutBlockEntry(t *testing.T) {
	cacheDir := makeCacheDir(t)
	defer unmakeCacheDir(t, cacheDir)
	fc, err := cache.NewFileSystem(cacheDir)
	testinggo.AssertNoError(t, err)
	r1 := &bcgo.Record{
		Timestamp: 1234,
		Payload:   []byte("Foo"),
	}
	rh1, err := cryptogo.HashProtobuf(r1)
	testinggo.AssertNoError(t, err)
	testinggo.AssertNoError(t, fc.PutBlockEntry("TEST", &bcgo.BlockEntry{
		Record:     r1,
		RecordHash: rh1,
	}))
	r2 := &bcgo.Record{
		Timestamp: 5678,
		Payload:   []byte("Bar"),
	}
	rh2, err := cryptogo.HashProtobuf(r2)
	testinggo.AssertNoError(t, err)
	testinggo.AssertNoError(t, fc.PutBlockEntry("TEST", &bcgo.BlockEntry{
		Record:     r2,
		RecordHash: rh2,
	}))
	files, err := ioutil.ReadDir(path.Join(cacheDir, "entry", "VEVTVA"))
	testinggo.AssertNoError(t, err)
	if len(files) != 2 {
		t.Fatalf("Block entries not written to storage; expected 2, got '%d'", len(files))
	}
	if files[0].Name() != "1234" {
		t.Fatalf("Incorrect file name; expected 1234, got '%s'", files[0].Name())
	}
	if files[1].Name() != "5678" {
		t.Fatalf("Incorrect file name; expected 5678, got '%s'", files[1].Name())
	}
}

func TestFileSystemBlockContainingRecord(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		cacheDir := makeCacheDir(t)
		defer unmakeCacheDir(t, cacheDir)
		fc, err := cache.NewFileSystem(cacheDir)
		testinggo.AssertNoError(t, err)
		_, err = fc.BlockContainingRecord("TEST", []byte("FOOBAR"))
		testinggo.AssertMatchesError(t, "^.*: no such file or directory", err)
	})
	t.Run("Exists", func(t *testing.T) {
		cacheDir := makeCacheDir(t)
		defer unmakeCacheDir(t, cacheDir)
		fc, err := cache.NewFileSystem(cacheDir)
		testinggo.AssertNoError(t, err)
		block := test.NewMockBlock(t, 1234)
		record := test.NewMockRecord(t)
		recordHash := test.NewHash(t, record)
		block.Entry = append(block.Entry, &bcgo.BlockEntry{
			Record:     record,
			RecordHash: recordHash,
		})
		hash := test.NewHash(t, block)
		testinggo.AssertNoError(t, fc.PutBlock(hash, block))
		b, err := fc.BlockContainingRecord("TEST", recordHash)
		testinggo.AssertNoError(t, err)
		testinggo.AssertProtobufEqual(t, block, b)
	})
}

func TestFileSystemHead(t *testing.T) {
	cacheDir := makeCacheDir(t)
	defer unmakeCacheDir(t, cacheDir)
	fc, err := cache.NewFileSystem(cacheDir)
	testinggo.AssertNoError(t, err)
	_, err = fc.Head("TEST")
	testinggo.AssertMatchesError(t, "^.*: no such file or directory", err)
}

func TestFileSystemPutHead(t *testing.T) {
	cacheDir := makeCacheDir(t)
	defer unmakeCacheDir(t, cacheDir)
	fc, err := cache.NewFileSystem(cacheDir)
	testinggo.AssertNoError(t, err)
	block := test.NewMockBlock(t, 1234)
	hash := test.NewHash(t, block)
	testinggo.AssertNoError(t, fc.PutHead("TEST", &bcgo.Reference{
		ChannelName: "TEST",
		BlockHash:   hash,
	}))
	ref, err := fc.Head("TEST")
	testinggo.AssertNoError(t, err)
	if ref.ChannelName != "TEST" {
		t.Fatalf("Expected error 'TEST', instead got '%s'", ref.ChannelName)
	}
	testinggo.AssertHashEqual(t, hash, ref.BlockHash)
}

func TestMeasureStorageUsage(t *testing.T) {
	t.Run("NoUsage", func(t *testing.T) {
		cacheDir := makeCacheDir(t)
		defer unmakeCacheDir(t, cacheDir)
		fc, err := cache.NewFileSystem(cacheDir)
		testinggo.AssertNoError(t, err)
		usage, err := fc.MeasureStorageUsage("")
		if err != nil {
			t.Fatalf("Expected no error")
		}
		if len(usage) != 0 {
			t.Fatalf("Expected no usage")
		}
	})
	t.Run("Usage", func(t *testing.T) {
		cacheDir := makeCacheDir(t)
		defer unmakeCacheDir(t, cacheDir)
		fc, err := cache.NewFileSystem(cacheDir)
		testinggo.AssertNoError(t, err)
		aliceRecord := &bcgo.Record{
			Creator: "Alice",
		}
		aliceRecordHash, err := cryptogo.HashProtobuf(aliceRecord)
		if err != nil {
			t.Fatalf("Expected no error, got " + err.Error())
		}
		aliceEntry := &bcgo.BlockEntry{
			RecordHash: aliceRecordHash,
			Record:     aliceRecord,
		}
		aliceExpected := uint64(proto.Size(aliceEntry))
		bobRecord := &bcgo.Record{
			Creator: "Bob",
		}
		bobRecordHash, err := cryptogo.HashProtobuf(bobRecord)
		if err != nil {
			t.Fatalf("Expected no error, got " + err.Error())
		}
		bobEntry := &bcgo.BlockEntry{
			RecordHash: bobRecordHash,
			Record:     bobRecord,
		}
		bobExpected := uint64(proto.Size(bobEntry))
		block := &bcgo.Block{
			ChannelName: "Test",
			Entry: []*bcgo.BlockEntry{
				aliceEntry,
				bobEntry,
			},
		}
		blockHash, err := cryptogo.HashProtobuf(block)
		if err != nil {
			t.Fatalf("Expected no error, got " + err.Error())
		}
		if err := fc.PutBlock(blockHash, block); err != nil {
			t.Fatalf("Expected no error, got " + err.Error())
		}
		usage, err := fc.MeasureStorageUsage("")
		if err != nil {
			t.Fatalf("Expected no error, got " + err.Error())
		}
		if len(usage) != 2 {
			t.Fatalf("Expected usage")
		}
		aliceUsage := usage["Alice"]
		if aliceUsage != aliceExpected {
			t.Fatalf("Incorrect usage; expected '%d', got '%d'", aliceExpected, aliceUsage)
		}
		bobUsage := usage["Bob"]
		if bobUsage != bobExpected {
			t.Fatalf("Incorrect usage; expected '%d', got '%d'", bobExpected, bobUsage)
		}
	})
}
