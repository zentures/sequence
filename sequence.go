// Copyright (c) 2014 Dataence, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sequence

import (
	"errors"
	"fmt"
	"strings"
)

//go:generate go run genmethods.go -- reqmethods.go
//go:generate go fmt reqmethods.go

var (
	ErrNoMatch = errors.New("sequence: no pattern matched for this message")
)

// Sequence represents a list of tokens returned from the scanner, analyzer or parser.
type Sequence []Token

// String returns a single line string that represents the pattern for the Sequence
func (this Sequence) String() string {
	var p string

	for _, token := range this {
		var c string

		if token.Tag != TagUnknown {
			c = token.Tag.String()

			if token.until != "" {
				c += ":-:" + token.until
			} else {
				if token.Type != token.Tag.TokenType() {
					c += ":" + token.Type.String()
				} else if token.plus || token.minus || token.star {
					c += ":"
				}

				if token.plus {
					c += ":+"
				} else if token.minus {
					c += ":-"
				} else if token.star {
					c += ":*"
				}
			}

			c = "%" + c + "%"
		} else if token.Type != TokenUnknown && token.Type != TokenLiteral {
			c = token.Type.String()

			if token.plus {
				c += ":+"
			} else if token.minus {
				c += ":-"
			} else if token.star {
				c += ":*"
			}

			c = "%" + c + "%"
		} else {
			c = token.Value
		}

		p += c + " "
	}

	return strings.TrimSpace(p)
}

// Signature returns a single line string that represents a common pattern for this
// types of messages, basically stripping any strings or literals from the message.
func (this Sequence) Signature() string {
	var sig string

	for _, token := range this {
		switch {
		case token.Type != TokenUnknown && token.Type != TokenString && token.Type != TokenLiteral:
			sig += "%" + token.Type.String() + "%"

		case token.Type == TokenLiteral && len(token.Value) == 1:
			sig += token.Value
		}
	}

	return sig
}

// Longstring returns a multi-line representation of the tokens in the sequence
func (this Sequence) PrintTokens() string {
	var str string
	for i, t := range this {
		str += fmt.Sprintf("# %3d: %s\n", i, t)
	}

	return str[:len(str)-1]
}
