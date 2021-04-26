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

const Alias = "TESTER"

func NewMockIdentity(t *testing.T, alias string) bcgo.Identity {
	return &MockIdentity{
		alias: alias,
	}
}

type MockIdentity struct {
	alias                                   string
	PublicKeyError                          error
	PlainText                               []byte
	EncryptAlgorithm                        cryptogo.EncryptionAlgorithm
	EncryptPayload                          []byte
	EncryptOutKey                           []byte
	EncryptError                            error
	EncryptKeyAlgorithm                     cryptogo.EncryptionAlgorithm
	EncryptKeyKey                           []byte
	EncryptKeyError                         error
	PlainTextKey                            []byte
	VerificationData, VerificationSignature []byte
	VerificationAlgorithm                   cryptogo.SignatureAlgorithm
	VerificationError                       error
}

func (a *MockIdentity) Alias() string {
	return a.alias
}

func (a *MockIdentity) PublicKey() (cryptogo.PublicKeyFormat, []byte, error) {
	return cryptogo.PublicKeyFormat_UNKNOWN_PUBLIC_KEY_FORMAT, nil, a.PublicKeyError
}

func (a *MockIdentity) Encrypt(payload []byte) (cryptogo.EncryptionAlgorithm, []byte, []byte, error) {
	a.PlainText = payload
	return a.EncryptAlgorithm, a.EncryptPayload, a.EncryptOutKey, a.EncryptError
}

func (a *MockIdentity) EncryptKey(key []byte) (cryptogo.EncryptionAlgorithm, []byte, error) {
	a.PlainTextKey = key
	return a.EncryptKeyAlgorithm, a.EncryptKeyKey, a.EncryptKeyError
}

func (a *MockIdentity) Verify(algorithm cryptogo.SignatureAlgorithm, data, signature []byte) error {
	a.VerificationAlgorithm = algorithm
	a.VerificationData = data
	a.VerificationSignature = signature
	return a.VerificationError
}
