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

import (
	//"errors"
	//"fmt"
	//"strconv"
	"time"
)

const (
	PERIOD_HOURLY = time.Hour
	PERIOD_DAILY  = PERIOD_HOURLY * 24
	PERIOD_YEARLY = PERIOD_HOURLY * 6366 // (265.25 * 24)

	THRESHOLD_PERIOD_HOUR = THRESHOLD_STANDARD
	THRESHOLD_PERIOD_DAY  = THRESHOLD_HARD
	THRESHOLD_PERIOD_YEAR = THRESHOLD_HARDEST
)

type PeriodicValidationChannel struct {
	Period time.Duration
}

type PeriodicValidator struct {
	Periods map[time.Duration]*PeriodicValidationChannel
}

func GetPeriodicValidator() *PeriodicValidator {
	return &PeriodicValidator{
		Periods: map[time.Duration]*PeriodicValidationChannel{
			PERIOD_HOURLY: &PeriodicValidationChannel{Period: PERIOD_HOURLY},
			PERIOD_DAILY:  &PeriodicValidationChannel{Period: PERIOD_DAILY},
			PERIOD_YEARLY: &PeriodicValidationChannel{Period: PERIOD_YEARLY},
		},
	}
}

func (p *PeriodicValidator) Validate(cache Cache, network Network, hash []byte, block *Block) error {
	// TODO
	return nil
}
