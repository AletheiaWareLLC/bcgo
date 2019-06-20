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
	"fmt"
	"github.com/AletheiaWareLLC/bcgo"
	"io/ioutil"
	"log"
)

func ExamplePoWChannelGetName() {
	channel := &bcgo.PoWChannel{
		Name:      "FooBar",
		Threshold: bcgo.THRESHOLD_STANDARD,
	}
	fmt.Println(channel.GetName())
	// Output:
	// FooBar
}

func ExamplePoWChannelString() {
	channel := &bcgo.PoWChannel{
		Name:      "FooBar",
		Threshold: bcgo.THRESHOLD_STANDARD,
	}
	fmt.Println(channel.String())
	// Output:
	// FooBar 288
}

func ExamplePoWChannelGetHead() {
	channel := &bcgo.PoWChannel{
		Name: "FooBar",
	}
	fmt.Println(channel.GetHead())
	// Output:
	// []
}

func ExamplePoWChannelUpdate() {
	channel := &bcgo.PoWChannel{
		Name: "FooBar",
	}
	cache := bcgo.NewMemoryCache(10)
	block := &bcgo.Block{
		ChannelName: "TEST",
		Length:      1,
	}
	hash, err := bcgo.HashProtobuf(block)
	if err != nil {
		log.Fatal("Could not hash block:", err)
	}
	if err := bcgo.Update(channel, cache, nil, hash, block); err != nil {
		log.Fatal("Could not update channel: ", err)
	}
	// Output:
	// FooBar updated to 1969-12-31 16:00:00 FWUibWQ62yof8r5ZeDq-frnkFLno_RioONTrlHrwjuaCRW8W_sMmcdYW3pcV-g4QLY8L-0Nl_Mx5oiwVkJKTEw
}

func ExamplePoWChannelUpdate_Threshold() {
	channel := &bcgo.PoWChannel{
		Name:      "FooBar",
		Threshold: bcgo.THRESHOLD_STANDARD,
	}
	cache := bcgo.NewMemoryCache(10)
	block := &bcgo.Block{
		ChannelName: "TEST",
		Length:      1,
	}
	hash, err := bcgo.HashProtobuf(block)
	if err != nil {
		log.Fatal("Could not hash block:", err)
	}
	fmt.Println(bcgo.Update(channel, cache, nil, hash, block))
	// Output: Chain invalid: Hash doesn't meet Proof-of-Work threshold: 262 vs 288
}

func ExamplePoWChannelUpdateGetHead() {
	channel := &bcgo.PoWChannel{
		Name: "FooBar",
	}
	cache := bcgo.NewMemoryCache(10)
	block := &bcgo.Block{
		ChannelName: "TEST",
		Length:      1,
	}
	hash, err := bcgo.HashProtobuf(block)
	if err != nil {
		log.Fatal("Could not hash block:", err)
	}
	if err := bcgo.Update(channel, cache, nil, hash, block); err != nil {
		log.Fatal("Could not update channel: ", err)
	}
	fmt.Println(channel.GetHead())
	// Output:
	// FooBar updated to 1969-12-31 16:00:00 FWUibWQ62yof8r5ZeDq-frnkFLno_RioONTrlHrwjuaCRW8W_sMmcdYW3pcV-g4QLY8L-0Nl_Mx5oiwVkJKTEw
	// [21 101 34 109 100 58 219 42 31 242 190 89 120 58 190 126 185 228 20 185 232 253 24 168 56 212 235 148 122 240 142 230 130 69 111 22 254 195 38 113 214 22 222 151 21 250 14 16 45 143 11 251 67 101 252 204 121 162 44 21 144 146 147 19]
}

func ExamplePoWChannelFileCache() {
	// Create temp directory
	dir, err := ioutil.TempDir("", "test")
	if err != nil {
		log.Fatal("Could not create temp cache dir:", err)
	}
	// Create file cache
	cache, err := bcgo.NewFileCache(dir)
	if err != nil {
		log.Fatal("Could not create file cache:", err)
	}

	// Create channel, update, and write to cache
	{
		channel := &bcgo.PoWChannel{
			Name: "FooBar",
		}
		block := &bcgo.Block{
			ChannelName: "TEST",
			Length:      1,
		}
		hash, err := bcgo.HashProtobuf(block)
		if err != nil {
			log.Fatal("Could not hash block:", err)
		}
		if err := bcgo.Update(channel, cache, nil, hash, block); err != nil {
			log.Fatal("Could not update channel: ", err)
		}
	}

	// Create channel and read from cache
	channel2 := &bcgo.PoWChannel{
		Name: "FooBar",
	}
	if err := bcgo.LoadHead(channel2, cache, nil); err != nil {
		log.Fatal("Could not load head from cache: ", err)
	}
	fmt.Println(channel2.GetHead())
	// Output:
	// FooBar updated to 1969-12-31 16:00:00 FWUibWQ62yof8r5ZeDq-frnkFLno_RioONTrlHrwjuaCRW8W_sMmcdYW3pcV-g4QLY8L-0Nl_Mx5oiwVkJKTEw
	// [21 101 34 109 100 58 219 42 31 242 190 89 120 58 190 126 185 228 20 185 232 253 24 168 56 212 235 148 122 240 142 230 130 69 111 22 254 195 38 113 214 22 222 151 21 250 14 16 45 143 11 251 67 101 252 204 121 162 44 21 144 146 147 19]
}
