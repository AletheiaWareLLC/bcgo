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
	"io/ioutil"
	"log"
)

func Channel_String() {
	channel := &bcgo.Channel{
		Name: "Foo",
	}
	fmt.Println(channel.String())
	// Output:
	// Foo
}

func Channel_Constructor_String() {
	channel := bcgo.NewChannel("Bar")
	fmt.Println(channel.String())
	// Output:
	// Bar
}

func Channel_GetHead_update() {
	channel := &bcgo.Channel{
		Name: "FooBar",
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
	if err := channel.Update(cache, nil, hash, block); err != nil {
		log.Fatal("Could not update channel: ", err)
	}
	fmt.Println(channel.Head)
	// Output:
	// FooBar updated to 1969-12-31 16:00:00 FWUibWQ62yof8r5ZeDq-frnkFLno_RioONTrlHrwjuaCRW8W_sMmcdYW3pcV-g4QLY8L-0Nl_Mx5oiwVkJKTEw
	// [21 101 34 109 100 58 219 42 31 242 190 89 120 58 190 126 185 228 20 185 232 253 24 168 56 212 235 148 122 240 142 230 130 69 111 22 254 195 38 113 214 22 222 151 21 250 14 16 45 143 11 251 67 101 252 204 121 162 44 21 144 146 147 19]
}

func Channel_filecache() {
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
		channel := &bcgo.Channel{
			Name: "FooBar",
		}
		block := &bcgo.Block{
			ChannelName: "TEST",
			Length:      1,
		}
		hash, err := cryptogo.HashProtobuf(block)
		if err != nil {
			log.Fatal("Could not hash block:", err)
		}
		if err := channel.Update(cache, nil, hash, block); err != nil {
			log.Fatal("Could not update channel: ", err)
		}
	}

	// Create channel and read from cache
	channel2 := &bcgo.Channel{
		Name: "FooBar",
	}
	if err := channel2.LoadHead(cache, nil); err != nil {
		log.Fatal("Could not load head from cache: ", err)
	}
	fmt.Println(channel2.Head)
	// Output:
	// FooBar updated to 1969-12-31 16:00:00 FWUibWQ62yof8r5ZeDq-frnkFLno_RioONTrlHrwjuaCRW8W_sMmcdYW3pcV-g4QLY8L-0Nl_Mx5oiwVkJKTEw
	// [21 101 34 109 100 58 219 42 31 242 190 89 120 58 190 126 185 228 20 185 232 253 24 168 56 212 235 148 122 240 142 230 130 69 111 22 254 195 38 113 214 22 222 151 21 250 14 16 45 143 11 251 67 101 252 204 121 162 44 21 144 146 147 19]
}
