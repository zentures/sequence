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

import "fmt"

type (
	// FieldType is the semantic representation of a token.
	FieldType int

	// Tokentype is the lexical representation of a token.
	TokenType int
)

// Token is a piece of information extracted from a log message. The Scanner will do
// its best to determine the TokenType which could be a time stamp, IPv4 or IPv6
// address, a URL, a mac address, an integer or a floating point number. In addition,
// if the Scanner finds a token that's surrounded by %, e.g., %srcuser%, it will
// try to determine the correct field type the token represents.
type Token struct {
	Type  TokenType // Type is the type of token the Value represents.
	Field FieldType // Field determines which field the Value should be.
	Value string    // Value is the extracted string from the log message.

	isValue bool // Is this token a key in k=v pair
	isKey   bool // Is this token a value in k=v pair

	minus bool // For parser, should this token consume the rest of the tokens
	plus  bool // For parser, should this token consume one or more tokens
	star  bool // For parser, should this token consume zero or more tokens

	until string // For parser, consume all tokens until, but not including, this string
}

func (this Token) String() string {
	return fmt.Sprintf("{ Field=%q, Type=%q, Value=%q, isKey=%t, isValue=%t, minus=%t, plus=%t, star=%t }", this.Field, this.Type, this.Value, this.isKey, this.isValue, this.minus, this.plus, this.star)
}

const (
	TokenUnknown   TokenType = iota // Unknown token
	TokenLiteral                    // Token is a fixed literal
	TokenTime                       // Token is a timestamp, in the format listed in TimeFormats
	TokenIPv4                       // Token is an IPv4 address, in the form of a.b.c.d
	TokenIPv6                       // Token is an IPv6 address
	TokenInteger                    // Token is an integer number
	TokenFloat                      // Token is a floating point number
	TokenURI                        // Token is an URL, in the form of http://... or https://...
	TokenMac                        // Token is a mac address
	TokenString                     // Token is a string that reprensents multiple possible values
	token__END__                    // All field types must be inserted before this one
	token__host__                   // Token is a host name
	token__email__                  // Token is an email address
)

var tokens = [...]struct {
	label string
}{
	{"tunknown"},
	{"literal"},
	{"time"},
	{"ipv4"},
	{"ipv6"},
	{"integer"},
	{"float"},
	{"uri"},
	{"mac"},
	{"string"},
	{"token__END__"},
	{"token__host__"},
	{"token__email__"},
}

func (this TokenType) String() string {
	return tokens[this].label
}

func (this FieldType) String() string {
	return config.fieldNames[this]
}

func (this FieldType) TokenType() TokenType {
	if int(this) < len(config.fieldTypes) {
		return config.fieldTypes[this]
	}

	return TokenUnknown
}

func name2TokenType(s string) TokenType {
	switch s {
	case "tunknown":
		return TokenUnknown
	case "literal":
		return TokenLiteral
	case "time":
		return TokenTime
	case "ipv4":
		return TokenIPv4
	case "ipv6":
		return TokenIPv6
	case "integer":
		return TokenInteger
	case "float":
		return TokenFloat
	case "url":
		return TokenURI
	case "mac":
		return TokenMac
	case "string":
		return TokenString
	case "token__END__":
		return token__END__
	case "token__host__":
		return token__host__
	case "token__email__":
		return token__email__
	}

	return TokenUnknown
}

func name2FieldType(s string) FieldType {
	if t, ok := config.fieldIDs[s]; ok {
		return t
	}

	return 0
}
