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
	DecryptAlgorithm    cryptogo.EncryptionAlgorithm
	DecryptPayload      []byte
	DecryptPlainText    []byte
	DecryptInKey        []byte
	DecryptError        error
	DecryptKeyAlgorithm cryptogo.EncryptionAlgorithm
	DecryptKeyKey       []byte
	DecryptKeyError     error
	SignatureAlgorithm  cryptogo.SignatureAlgorithm
	Signature           []byte
	SignatureError      error
}

func (a *MockAccount) Decrypt(algorithm cryptogo.EncryptionAlgorithm, payload, key []byte) ([]byte, error) {
	a.DecryptAlgorithm = algorithm
	a.DecryptPayload = payload
	a.DecryptInKey = key
	return a.DecryptPlainText, a.DecryptError
}

func (a *MockAccount) DecryptKey(algorithm cryptogo.EncryptionAlgorithm, key []byte) ([]byte, error) {
	a.DecryptKeyAlgorithm = algorithm
	a.DecryptKeyKey = key
	return a.PlainTextKey, a.DecryptKeyError
}

func (a *MockAccount) Sign(data []byte) (cryptogo.SignatureAlgorithm, []byte, error) {
	return a.SignatureAlgorithm, a.Signature, a.SignatureError
}
