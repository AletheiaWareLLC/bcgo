/*
 * Copyright 2021 Aletheia Ware LLC
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

package test

import (
	"aletheiaware.com/bcgo"
	"aletheiaware.com/cryptogo"
	"testing"
)

func NewMockRecord(t *testing.T) *bcgo.Record {
	t.Helper()
	return &bcgo.Record{
		Timestamp: 9012,
		Creator:   "TESTER",

		Access: []*bcgo.Record_Access{
			&bcgo.Record_Access{
				Alias:               "TESTER",
				SecretKey:           []byte("SECRET"),
				EncryptionAlgorithm: cryptogo.EncryptionAlgorithm_RSA_ECB_OAEPPADDING,
			},
		},
		Payload:              []byte("DATA"),
		CompressionAlgorithm: cryptogo.CompressionAlgorithm_UNKNOWN_COMPRESSION,
		EncryptionAlgorithm:  cryptogo.EncryptionAlgorithm_AES_128_GCM_NOPADDING,
		Signature:            []byte("SIGN"),
		SignatureAlgorithm:   cryptogo.SignatureAlgorithm_SHA512WITHRSA_PSS,
		Reference: []*bcgo.Reference{
			&bcgo.Reference{
				Timestamp:   8901,
				ChannelName: "FOOBAR",
				BlockHash:   []byte("OTHERBLOCK"),
				RecordHash:  []byte("OTHERRECORD"),
			},
		},
	}
}
