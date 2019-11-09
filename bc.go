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

package bcgo

const (
	THRESHOLD_NONE     = 0
	THRESHOLD_EASIEST  = 264 // 33/64
	THRESHOLD_EASY     = 272 // 17/32
	THRESHOLD_STANDARD = 288 // 9/16
	THRESHOLD_HARD     = 320 // 5/8
	THRESHOLD_HARDEST  = 384 // 3/4

	MAX_BLOCK_SIZE_BYTES   = uint64(2 * 1024 * 1024 * 1024) // 2Gb
	MAX_PAYLOAD_SIZE_BYTES = uint64(10 * 1024 * 1024)       // 10Mb
)
