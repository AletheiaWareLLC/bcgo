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
	"aletheiaware.com/bcgo"
	"aletheiaware.com/cryptogo"
	"fmt"
	"log"
)

func ExamplePoWValidator_Threshold() {
	validator := &bcgo.PoWValidator{
		Threshold: bcgo.THRESHOLD_G,
	}
	channel := &bcgo.Channel{
		Name: "FooBar",
		Validators: []bcgo.Validator{
			validator,
		},
	}
	cache := bcgo.NewMemoryCache(10)
	block := &bcgo.Block{
		ChannelName: "TEST",
		Length:      1,
	}
	hash, err := cryptogo.HashProtobuf(block)
	if err != nil {
		log.Fatal("Could not hash block:", err)
	}
	fmt.Println(validator.Validate(channel, cache, nil, hash, block))
	// Output: Hash doesn't meet Proof-of-Work threshold: 262 vs 288
}
