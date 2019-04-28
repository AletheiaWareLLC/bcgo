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
	"testing"
)

func TestPrinterBlock(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		block := &bcgo.Block{}
		hash := makeHash(t, block)
		bcgo.PrintBlock(buffer, "", hash, block)
		expected := `Hash: z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg_SpIdNs6c5H0NE8XYXysP-DGNKHfuwvY7kxvUdBeoGlODJ6-SfaPg
Timestamp: 0
ChannelName: 
Length: 0
Previous: 
Miner: 
Nonce: 0
Entries: 0
`
		actual := buffer.String()
		if actual != expected {
			t.Fatalf("Print failed; epected '%s', got '%s'", expected, actual)
		}
	})
	t.Run("Full", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		record := makeRecord(t)
		recordHash := makeHash(t, record)
		block := &bcgo.Block{
			ChannelName: "Foo",
			Length:      1,
			Miner:       "Bar",
			Nonce:       2,
			Entry: []*bcgo.BlockEntry{
				&bcgo.BlockEntry{
					RecordHash: recordHash,
					Record:     record,
				},
			},
		}
		hash := makeHash(t, block)
		bcgo.PrintBlock(buffer, "", hash, block)
		expected := `Hash: Id_wPRS4LMFly6VddtGZTCdQavCJBrnBx-4SYYQZjpAoMPecVRoEvUNG57l6pwdUQ4_TMmVTqxLCDXGfvULwOg
Timestamp: 0
ChannelName: Foo
Length: 1
Previous: 
Miner: Bar
Nonce: 2
Entries: 1
Entry: 0
	Hash: Djo1eAULru-kuhL5F3mu15DVb4ma2SmK4MC47E79AeeIefX0cD-DfcBvzh4JApPAcQRVQvtahNe0dy9XSsSXHg
	Timestamp: 9012
	Creator: TESTER
	Access: 0
		Alias: TESTER
		SecretKey: U0VDUkVU
		KeyEncryptionAlgorithm: RSA_ECB_OAEPPADDING
	Payload: REFUQQ
	CompressionAlgorithm: UNKNOWN_COMPRESSION
	EncryptionAlgorithm: AES_GCM_NOPADDING
	Signature: U0lHTg
	SignatureAlgorithm: SHA512WITHRSA_PSS
	References: 1
	Reference: 0
		Timestamp: 8901
		ChannelName: FOOBAR
		BlockHash: T1RIRVJCTE9DSw
		RecordHash: T1RIRVJSRUNPUkQ
`
		actual := buffer.String()
		if actual != expected {
			t.Fatalf("Print failed; epected '%s', got '%s'", expected, actual)
		}
	})
}

func TestPrinterBlockEntry(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		entry := &bcgo.BlockEntry{}
		bcgo.PrintBlockEntry(buffer, "", entry)
		expected := `Hash: 
Record: <nil>
`
		actual := buffer.String()
		if actual != expected {
			t.Fatalf("Print failed; epected '%s', got '%s'", expected, actual)
		}
	})
	t.Run("Full", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		record := makeRecord(t)
		recordHash := makeHash(t, record)
		entry := &bcgo.BlockEntry{
			RecordHash: recordHash,
			Record:     record,
		}
		bcgo.PrintBlockEntry(buffer, "", entry)
		expected := `Hash: Djo1eAULru-kuhL5F3mu15DVb4ma2SmK4MC47E79AeeIefX0cD-DfcBvzh4JApPAcQRVQvtahNe0dy9XSsSXHg
Timestamp: 9012
Creator: TESTER
Access: 0
	Alias: TESTER
	SecretKey: U0VDUkVU
	KeyEncryptionAlgorithm: RSA_ECB_OAEPPADDING
Payload: REFUQQ
CompressionAlgorithm: UNKNOWN_COMPRESSION
EncryptionAlgorithm: AES_GCM_NOPADDING
Signature: U0lHTg
SignatureAlgorithm: SHA512WITHRSA_PSS
References: 1
Reference: 0
	Timestamp: 8901
	ChannelName: FOOBAR
	BlockHash: T1RIRVJCTE9DSw
	RecordHash: T1RIRVJSRUNPUkQ
`
		actual := buffer.String()
		if actual != expected {
			t.Fatalf("Print failed; epected '%s', got '%s'", expected, actual)
		}
	})
}

func TestPrinterReference(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		reference := &bcgo.Reference{}
		bcgo.PrintReference(buffer, "", reference)
		expected := `Timestamp: 0
ChannelName: 
BlockHash: 
RecordHash: 
`
		actual := buffer.String()
		if actual != expected {
			t.Fatalf("Print failed; epected '%s', got '%s'", expected, actual)
		}
	})
	t.Run("Full", func(t *testing.T) {
		buffer := &bytes.Buffer{}
		reference := &bcgo.Reference{
			Timestamp:   1234,
			ChannelName: "FooBar",
			BlockHash:   []byte("BLOCK"),
			RecordHash:  []byte("RECORD"),
		}
		bcgo.PrintReference(buffer, "", reference)
		expected := `Timestamp: 1234
ChannelName: FooBar
BlockHash: QkxPQ0s
RecordHash: UkVDT1JE
`
		actual := buffer.String()
		if actual != expected {
			t.Fatalf("Print failed; epected '%s', got '%s'", expected, actual)
		}
	})
}
