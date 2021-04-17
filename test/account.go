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

func NewMockAccount(t *testing.T, alias string) bcgo.Account {
	return &MockAccount{
		MockIdentity: MockIdentity{
			alias: alias,
		},
	}
}

type MockAccount struct {
	MockIdentity
	DecryptionEntry                       *bcgo.BlockEntry
	DecryptionAccess, DecryptionKeyAccess *bcgo.Record_Access
	DecryptionError, DecryptionKeyError   error
	Signature                             []byte
	SignatureAlgorithm                    cryptogo.SignatureAlgorithm
	SignatureError                        error
}

func (a *MockAccount) Decrypt(entry *bcgo.BlockEntry, access *bcgo.Record_Access, callback func(*bcgo.BlockEntry, []byte, []byte) error) error {
	a.DecryptionEntry = entry
	a.DecryptionAccess = access
	return a.DecryptionError
}

func (a *MockAccount) DecryptKey(access *bcgo.Record_Access, callback func([]byte) error) error {
	a.DecryptionKeyAccess = access
	return a.DecryptionKeyError
}

func (a *MockAccount) Sign(data []byte) ([]byte, cryptogo.SignatureAlgorithm, error) {
	return a.Signature, a.SignatureAlgorithm, a.SignatureError
}
