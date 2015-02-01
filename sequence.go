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
	"fmt"
	"strings"
)

//go:generate go run gentokens.go -- tokens.go
//go:generate go fmt tokens.go

// Sequence represents a list of tokens returned from the scanner, analyzer or parser.
type Sequence []Token

// String returns a single line string that represents the pattern for the Sequence
func (this Sequence) String() string {
	var p string

	for _, token := range this {
		if token.Field != FieldUnknown {
			p += token.Field.String() + " "
		} else if token.Type != TokenUnknown && token.Type != TokenLiteral {
			p += token.Type.String() + " "
		} else if token.Type == TokenLiteral {
			p += token.Value + " "
		}
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
			sig += token.Type.String()

		case token.Type == TokenLiteral && len(token.Value) == 1:
			sig += token.Value
		}
	}

	return sig
}

// Longstring returns a multi-line representation of the tokens in the sequence
func (this Sequence) LongString() string {
	var str string
	for i, t := range this {
		str += fmt.Sprintf("# %3d: %s\n", i, t)
	}

	return str[:len(str)-1]
}
