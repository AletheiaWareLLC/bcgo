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

func (a *MockIdentity) PublicKey() ([]byte, cryptogo.PublicKeyFormat, error) {
	return nil, cryptogo.PublicKeyFormat_UNKNOWN_PUBLIC_KEY_FORMAT, a.PublicKeyError
}

func (a *MockIdentity) EncryptKey(key []byte) ([]byte, cryptogo.EncryptionAlgorithm, error) {
	a.PlainTextKey = key
	return a.EncryptKeyKey, a.EncryptKeyAlgorithm, a.EncryptKeyError
}

func (a *MockIdentity) Verify(data, signature []byte, algorithm cryptogo.SignatureAlgorithm) error {
	a.VerificationData = data
	a.VerificationSignature = signature
	a.VerificationAlgorithm = algorithm
	return a.VerificationError
}
