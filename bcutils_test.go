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
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/cryptogo"
	"github.com/AletheiaWareLLC/testinggo"
	"github.com/golang/protobuf/proto"
	"io/ioutil"
	"os"
	"os/user"
	"regexp"
	"testing"
)

func setEnv(t *testing.T, key, value string) {
	t.Helper()
	os.Setenv(key, value)
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	os.Unsetenv(key)
}

func TestBinarySizeToString(t *testing.T) {
	sizeTests := []struct {
		given    uint64
		expected string
	}{
		{0, "0Bytes"},
		{1, "1Byte"},
		{64, "64Bytes"},
		{1234, "1.21KiB"},
		{56789, "55.46KiB"},
		{1234567, "1.18MiB"},
		{8901234567, "8.29GiB"},
		{8901234567890, "8.1TiB"},
		{12345678901234567, "10.97PiB"},
	}
	for _, test := range sizeTests {
		got := bcgo.BinarySizeToString(test.given)
		if got != test.expected {
			t.Fatalf("expected %s, instead got %s", test.expected, got)
		}
	}
}

func TestDecimalSizeToString(t *testing.T) {
	sizeTests := []struct {
		given    uint64
		expected string
	}{
		{0, "0Bytes"},
		{1, "1Byte"},
		{64, "64Bytes"},
		{1234, "1.23KB"},
		{56789, "56.79KB"},
		{1234567, "1.23MB"},
		{8901234567, "8.9GB"},
		{8901234567890, "8.9TB"},
		{12345678901234567, "12.35PB"},
	}
	for _, test := range sizeTests {
		got := bcgo.DecimalSizeToString(test.given)
		if got != test.expected {
			t.Fatalf("expected %s, instead got %s", test.expected, got)
		}
	}
}

func TestTimestampToString(t *testing.T) {
	given := uint64(1565656565656565656)
	expected := "2019-08-13 00:36:05"
	got := bcgo.TimestampToString(given)
	if got != expected {
		t.Fatalf("expected %s, instead got %s", expected, got)
	}
}

func TestMoneyToString(t *testing.T) {
	moneyTests := []struct {
		given    int64
		expected string
	}{
		{0, "Free"},
		{1, "$0.01"},
		{64, "$0.64"},
		{1234, "$12.34"},
		{56789, "$567.89"},
		{1234567, "$12345.67"},
		{8901234567, "$89012345.67"},
		{8901234567890, "$89012345678.9"},
		// TODO test negative amounts
	}
	for _, test := range moneyTests {
		got := bcgo.MoneyToString("usd", test.given)
		if got != test.expected {
			t.Fatalf("expected %s, instead got %s", test.expected, got)
		}
	}
}

func TestGetAlias(t *testing.T) {
	t.Run("EnvUnset", func(t *testing.T) {
		unsetEnv(t, "ALIAS")
		alias, err := bcgo.GetAlias()
		testinggo.AssertNoError(t, err)
		u, err := user.Current()
		testinggo.AssertNoError(t, err)
		if alias != u.Username {
			t.Fatalf("Incorrect alias; expected '%s', got '%s'", u.Username, alias)
		}
	})
	t.Run("EnvSet", func(t *testing.T) {
		setEnv(t, "ALIAS", "foobar123")
		defer unsetEnv(t, "ALIAS")
		alias, err := bcgo.GetAlias()
		testinggo.AssertNoError(t, err)
		if alias != "foobar123" {
			t.Fatalf("Incorrect alias; expected '%s', got '%s'", "foobar123", alias)
		}
	})
}

func TestGetRootDir(t *testing.T) {
	t.Run("EnvUnset", func(t *testing.T) {
		unsetEnv(t, "ROOT_DIRECTORY")
		root, err := bcgo.GetRootDirectory()
		testinggo.AssertNoError(t, err)
		match, err := regexp.MatchString("^/.*/bc$", root)
		testinggo.AssertNoError(t, err)
		if !match {
			t.Fatalf("Incorrect root directory; expected root in homedir, got '%s'", root)
		}
	})
	t.Run("EnvSet", func(t *testing.T) {
		setEnv(t, "ROOT_DIRECTORY", "foobar123")
		defer unsetEnv(t, "ROOT_DIRECTORY")
		root, err := bcgo.GetRootDirectory()
		testinggo.AssertNoError(t, err)
		if root != "foobar123" {
			t.Fatalf("Incorrect root directory; expected foobar123, got '%s'", root)
		}
	})
}

func TestGetCacheDir(t *testing.T) {
	t.Run("EnvUnset", func(t *testing.T) {
		unsetEnv(t, "CACHE_DIRECTORY")
		temp, err := ioutil.TempDir("", "foobar")
		defer os.Remove(temp)
		cache, err := bcgo.GetCacheDirectory(temp)
		testinggo.AssertNoError(t, err)
		match, err := regexp.MatchString("^"+temp+"/cache$", cache)
		testinggo.AssertNoError(t, err)
		if !match {
			t.Fatalf("Incorrect cache directory; expected cache in homedir, got '%s'", cache)
		}
	})
	t.Run("EnvSet", func(t *testing.T) {
		setEnv(t, "CACHE_DIRECTORY", "foobar123")
		defer unsetEnv(t, "CACHE_DIRECTORY")
		cache, err := bcgo.GetCacheDirectory("/foobar")
		testinggo.AssertNoError(t, err)
		if cache != "foobar123" {
			t.Fatalf("Incorrect cache directory; expected foobar123, got '%s'", cache)
		}
	})
}

func TestCreateRecord(t *testing.T) {
	t.Run("Encrypted", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Error("Could not generate key:", err)
		}
		acl := map[string]*rsa.PublicKey{
			"TESTER": &key.PublicKey,
		}
		k, record, err := bcgo.CreateRecord(1234, "TESTER", key, acl, nil, []byte("PAYLOAD"))
		testinggo.AssertNoError(t, err)
		if len(k) == 0 {
			t.Fatalf("Record key is empty")
		}
		if record.Timestamp != 1234 {
			t.Fatalf("Incorrect record timestamp")
		}
		if len(record.Access) != 1 {
			t.Fatalf("Record access list empty")
		}
		if record.Access[0].Alias != "TESTER" {
			t.Fatalf("Incorrect record access alias")
		}
		if record.EncryptionAlgorithm != cryptogo.EncryptionAlgorithm_AES_256_GCM_NOPADDING {
			t.Fatalf("Incorrect record encryption algorithm")
		}
	})
	t.Run("Unencrypted", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Error("Could not generate key:", err)
		}
		k, record, err := bcgo.CreateRecord(1234, "TESTER", key, nil, nil, []byte("PAYLOAD"))
		testinggo.AssertNoError(t, err)
		if len(k) != 0 {
			t.Fatalf("Record key is not empty")
		}
		if record.Timestamp != 1234 {
			t.Fatalf("Incorrect record timestamp")
		}
		if record.EncryptionAlgorithm != cryptogo.EncryptionAlgorithm_UNKNOWN_ENCRYPTION {
			t.Fatalf("Incorrect record encryption algorithm")
		}
	})
}

func writeReadBuffer(t *testing.T, buffer *bytes.Buffer, proto1, proto2 proto.Message) {
	t.Helper()
	testinggo.AssertNoError(t, bcgo.WriteDelimitedProtobuf(bufio.NewWriter(buffer), proto1))
	testinggo.AssertNoError(t, bcgo.ReadDelimitedProtobuf(bufio.NewReader(buffer), proto2))
	testinggo.AssertProtobufEqual(t, proto1, proto2)
}

func TestDelimitedProtobuf(t *testing.T) {
	t.Run("SmallBlock", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		block1 := &bcgo.Block{
			ChannelName: "Test",
		}
		block2 := &bcgo.Block{}
		writeReadBuffer(t, buffer, block1, block2)
	})
	t.Run("BigBlock", func(t *testing.T) {
		longName := make([]byte, bcgo.MAX_PAYLOAD_SIZE_BYTES+1)
		buffer := &bytes.Buffer{}
		block1 := &bcgo.Block{
			Timestamp:   1234,
			ChannelName: "Test" + string(longName),
			Length:      1,
		}
		block2 := &bcgo.Block{}
		writeReadBuffer(t, buffer, block1, block2)
	})
	t.Run("Reference", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		reference1 := &bcgo.Reference{
			Timestamp:   1234,
			ChannelName: "Test",
			BlockHash:   []byte("FooBar"),
		}
		reference2 := &bcgo.Reference{}
		writeReadBuffer(t, buffer, reference1, reference2)
	})
}
