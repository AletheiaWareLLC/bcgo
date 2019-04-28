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
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/testinggo"
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

func TestFileCacheGetBlock(t *testing.T) {
	cacheDir := makeCacheDir(t)
	defer unmakeCacheDir(t, cacheDir)
	fc, err := bcgo.NewFileCache(cacheDir)
	testinggo.AssertNoError(t, err)
	block := makeBlock(t, 1234)
	hash := makeHash(t, block)
	_, err = fc.GetBlock(hash)
	testinggo.AssertMatchesError(t, "^.*: no such file or directory", err)
}

func TestFileCachePutBlock(t *testing.T) {
	cacheDir := makeCacheDir(t)
	defer unmakeCacheDir(t, cacheDir)
	fc, err := bcgo.NewFileCache(cacheDir)
	testinggo.AssertNoError(t, err)
	block := makeBlock(t, 1234)
	hash := makeHash(t, block)
	testinggo.AssertNoError(t, fc.PutBlock(hash, block))
	b, err := fc.GetBlock(hash)
	testinggo.AssertNoError(t, err)
	testinggo.AssertProtobufEqual(t, block, b)
}

// func TestFileCacheDeleteBlock(t *testing.T) {
// 	cacheDir := makeCacheDir(t)
// 	defer unmakeCacheDir(t, cacheDir)
// 	fc, err := bcgo.NewFileCache(cacheDir)
// 	testinggo.AssertNoError(t, err)
// 	block := makeBlock(t, 1234)
// 	hash := makeHash(t, block)
// 	testinggo.AssertNoError(t, fc.PutBlock(hash, block))
// 	testinggo.AssertNoError(t, fc.DeleteBlock(hash))
// 	_, err = fc.GetBlock(hash)
// 	testinggo.AssertMatchesError(t, "^.*: no such file or directory", err)
// }

func TestFileCacheGetBlockEntries(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		cacheDir := makeCacheDir(t)
		defer unmakeCacheDir(t, cacheDir)
		fc, err := bcgo.NewFileCache(cacheDir)
		testinggo.AssertNoError(t, err)
		_, err = fc.GetBlockEntries("TEST", 0)
		testinggo.AssertMatchesError(t, "^.*: no such file or directory", err)
	})
	t.Run("Timestamp", func(t *testing.T) {
		cacheDir := makeCacheDir(t)
		defer unmakeCacheDir(t, cacheDir)
		fc, err := bcgo.NewFileCache(cacheDir)
		testinggo.AssertNoError(t, err)
		r1 := &bcgo.Record{
			Timestamp: 1234,
			Payload:   []byte("Foo"),
		}
		rh1, err := bcgo.HashProtobuf(r1)
		testinggo.AssertNoError(t, err)
		testinggo.AssertNoError(t, fc.PutBlockEntry("TEST", &bcgo.BlockEntry{
			Record:     r1,
			RecordHash: rh1,
		}))
		r2 := &bcgo.Record{
			Timestamp: 5678,
			Payload:   []byte("Bar"),
		}
		rh2, err := bcgo.HashProtobuf(r2)
		testinggo.AssertNoError(t, err)
		testinggo.AssertNoError(t, fc.PutBlockEntry("TEST", &bcgo.BlockEntry{
			Record:     r2,
			RecordHash: rh2,
		}))
		entries, err := fc.GetBlockEntries("TEST", 3456)
		testinggo.AssertNoError(t, err)
		if len(entries) != 1 {
			t.Fatalf("Incorrect entries; expected 1, got '%d'", len(entries))
		}
		if !bytes.Equal(entries[0].Record.Payload, []byte("Bar")) {
			t.Fatalf("Incorrect entry; expected Bar, got '%s'", entries[0].Record.Payload)
		}
	})
}

func TestFileCachePutBlockEntry(t *testing.T) {
	cacheDir := makeCacheDir(t)
	defer unmakeCacheDir(t, cacheDir)
	fc, err := bcgo.NewFileCache(cacheDir)
	testinggo.AssertNoError(t, err)
	r1 := &bcgo.Record{
		Timestamp: 1234,
		Payload:   []byte("Foo"),
	}
	rh1, err := bcgo.HashProtobuf(r1)
	testinggo.AssertNoError(t, err)
	testinggo.AssertNoError(t, fc.PutBlockEntry("TEST", &bcgo.BlockEntry{
		Record:     r1,
		RecordHash: rh1,
	}))
	r2 := &bcgo.Record{
		Timestamp: 5678,
		Payload:   []byte("Bar"),
	}
	rh2, err := bcgo.HashProtobuf(r2)
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

func TestFileCacheGetHead(t *testing.T) {
	cacheDir := makeCacheDir(t)
	defer unmakeCacheDir(t, cacheDir)
	fc, err := bcgo.NewFileCache(cacheDir)
	testinggo.AssertNoError(t, err)
	_, err = fc.GetHead("TEST")
	testinggo.AssertMatchesError(t, "^.*: no such file or directory", err)
}

func TestFileCachePutHead(t *testing.T) {
	cacheDir := makeCacheDir(t)
	defer unmakeCacheDir(t, cacheDir)
	fc, err := bcgo.NewFileCache(cacheDir)
	testinggo.AssertNoError(t, err)
	block := makeBlock(t, 1234)
	hash := makeHash(t, block)
	testinggo.AssertNoError(t, fc.PutHead("TEST", &bcgo.Reference{
		ChannelName: "TEST",
		BlockHash:   hash,
	}))
	ref, err := fc.GetHead("TEST")
	testinggo.AssertNoError(t, err)
	if ref.ChannelName != "TEST" {
		t.Fatalf("Expected error 'TEST', instead got '%s'", ref.ChannelName)
	}
	testinggo.AssertHashEqual(t, hash, ref.BlockHash)
}
