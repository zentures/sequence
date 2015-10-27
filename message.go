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
	"io"
	"unicode"
)

type Message struct {
	Data string

	state struct {
		// these are per token states
		tokenType TokenType
		tokenStop bool
		dots      int
		initDot   bool // Did the token start w/ a dot?
		octets    int  // number of octets found for ipv4

		// these are per message states
		prevToken       Token
		tokCount        int
		cur, start, end int // cursor positions

		backslash bool // Should the next quote be escaped?

		inquote bool // Are we inside a quote such as ", ', <, [
		chquote rune // Which quote character is it?
		nxquote bool // Should the next quote be an open quote? See special case in scan()

		hexState            int  // Current hex string state
		hexStart            bool // Is the first char a :?
		hexColons           int  // Total number of colons
		hexSuccColons       int  // The current number of successive colons
		hexMaxSuccColons    int  // Maximum number of successive colons
		hexSuccColonsSeries int  // Number of successive colon series
	}
}

const (
	hexStart = iota
	hexChar1
	hexChar2
	hexChar3
	hexChar4
	hexColon
)

// Scan is similar to Tokenize except it returns one token at a time
func (this *Message) Tokenize() (Token, error) {
	if this.state.start < this.state.end {
		// Number of spaces skipped
		nss := this.skipSpace(this.Data[this.state.start:])
		this.state.start += nss

		// Let's see if this is a tag token, enclosed in two '%' chars
		// at least 2 chars left, and the first is a '%'
		if this.state.start+1 < this.state.end && this.Data[this.state.start] == '%' {
			var i int
			var r rune

			for i, r = range this.Data[this.state.start+1:] {
				if !isTagTokenChar(r) {
					break
				}
			}

			if r == '%' && i > 0 {
				tok := Token{
					Tag:   TagUnknown,
					Type:  TokenLiteral,
					Value: this.Data[this.state.start : this.state.start+i+2],
				}

				this.state.start += i + 2

				return tok, nil
			}
		}

		l, t, err := this.scanToken(this.Data[this.state.start:])
		if err != nil {
			return Token{}, err
		} else if l == 0 {
			return Token{}, io.EOF
		} else if t == TokenUnknown {
			return Token{}, fmt.Errorf("unknown token encountered: %s\n%v", this.Data[this.state.start:], t)
		}

		// remove any trailing spaces
		s := 0 // trail space count
		for this.Data[this.state.start+l-1] == ' ' && l > 0 {
			l--
			s++
		}

		tok := Token{Tag: TagUnknown, Type: t, Value: this.Data[this.state.start : this.state.start+l]}
		this.state.tokCount++
		this.state.prevToken = tok
		this.state.start += l + s

		//this.state.start += this.skipSpace(this.Data[this.state.start:])

		return tok, nil
	}

	return Token{}, io.EOF
}

func (this *Message) skipSpace(data string) int {
	// Skip leading spaces.
	i := 0

	for _, r := range data {
		if !unicode.IsSpace(r) {
			break
		} else {
			i++
		}
	}

	return i
}

func (this *Message) scanToken(data string) (int, TokenType, error) {
	var (
		tnode                                  = timeFsmRoot
		tokenStop, timeStop, hexStop, hexValid bool
		timeLen, hexLen, tokenLen              int
		l                                      = len(data)
	)

	this.resetTokenStates()

	// short circuit the time check
	if l < 3 {
		hexStop = true
	}

	// short circuit the time check
	if l < minTimeLength {
		timeStop = true
	}

	for i, r := range data {
		if !tokenStop {
			tokenStop = this.tokenStep(i, r)

			if !tokenStop {
				tokenLen++
			}
		}

		if !hexStop {
			hexValid, hexStop = this.hexStep(i, r)

			if hexValid {
				hexLen = i + 1
			}
		}

		if !timeStop {
			if tnode = timeStep(r, tnode); tnode == nil {
				timeStop = true

				if timeLen > 0 {
					return timeLen, TokenTime, nil
				}
			} else if tnode.final == TokenTime {
				if i+1 > timeLen {
					timeLen = i + 1
				}
			}
		}

		// glog.Debugf("i=%d, r=%c, tokenStop=%t, timeStop=%t, hexStop=%t", i, r, this.state.tokenStop, timeStop, hexStop)
		// This means either we found something, or we have exhausted the string
		if (tokenStop && timeStop && hexStop) || i == l-1 {
			if timeLen > 0 {
				return timeLen, TokenTime, nil
			} else if hexLen > 0 && this.state.hexColons > 1 {
				if this.state.hexColons == 5 && this.state.hexMaxSuccColons == 1 {
					return hexLen, TokenMac, nil
				} else if this.state.hexSuccColonsSeries == 1 ||
					(this.state.hexColons == 7 && this.state.hexSuccColonsSeries == 0) {

					return hexLen, TokenIPv6, nil
				} else {
					return hexLen, TokenLiteral, nil
				}
			}

			// glog.Debugf("i=%d, r=%c, tokenLen=%d, value=%q", i, r, tokenLen, data[:tokenLen])
			// If token length is 0, it means we didn't find time, nor did we find
			// a word, it cannot be space since we skipped all space. This means it
			// is a single character literal, so return that.
			if tokenLen == 0 {
				return 1, TokenLiteral, nil
			} else {
				switch this.state.tokenType {
				case TokenIPv4:
					if this.state.dots != 3 {
						this.state.tokenType = TokenLiteral
					}

				case TokenFloat:
					if r == '.' && i == l-1 {
						tokenLen--
						this.state.tokenType = TokenInteger
					}
				}

				return tokenLen, this.state.tokenType, nil
			}
		}
	}

	return len(data), this.state.tokenType, nil
}

func (this *Message) tokenStep(i int, r rune) bool {
	// glog.Debugf("1. i=%d, r=%c, tokenStop=%t, tokenType=%s", i, r, this.state.tokenStop, this.state.tokenType)
	switch this.state.tokenType {
	case TokenUnknown:
		switch r {
		case 'h', 'H':
			this.state.tokenType = TokenURI

		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			this.state.tokenType = TokenInteger

		// case '.':
		// 	this.state.tokenType = TokenFloat
		// 	this.state.initDot = true

		case '/':
			if this.state.prevToken.Type == TokenIPv4 {
				this.state.tokenType = TokenLiteral
				this.state.tokenStop = true
			}

		case '"', '\'':
			this.state.tokenStop = true
			this.state.tokenType = TokenLiteral
			//glog.Debugf("i=%d, r=%c, inquote=%t, nxquote=%t, chquote=%c", i, r, this.state.inquote, this.state.nxquote, this.state.chquote)

			if !this.state.inquote && this.state.nxquote {
				// If we are not inside a quote now and we are at the beginning,
				// then let's be inside the quote now. This is basically the
				// beginning quotation mark.
				this.state.inquote = true
				this.state.chquote = r
				this.state.nxquote = true
			} else if this.state.inquote && this.state.chquote == r {
				// If we are at the beginning of the data and we are inside a quote,
				// then this is the ending quotation mark.
				this.state.inquote = false
			} else if !this.state.inquote && !this.state.nxquote {
				this.state.nxquote = true
			}

			//glog.Debugf("i=%d, r=%c, inquote=%t, nxquote=%t, chquote=%c", i, r, this.state.inquote, this.state.nxquote, this.state.chquote)

		case '<':
			this.state.tokenStop = true
			this.state.tokenType = TokenLiteral

			if !this.state.inquote {
				// If we are not inside a quote now and we are at the beginning,
				// then let's be inside the quote now. This is basically the
				// beginning quotation mark.
				this.state.inquote = true
				this.state.chquote = r
			}

		case '>':
			this.state.tokenStop = true
			this.state.tokenType = TokenLiteral

			if this.state.inquote && this.state.chquote == '<' {
				// If we are at the beginning of the data and we are inside a quote,
				// then this is the ending quotation mark.
				this.state.inquote = false
			}

		case '\\':
			this.state.tokenType = TokenLiteral

		default:
			this.state.tokenType = TokenLiteral
			if !isLiteral(r) {
				this.state.tokenStop = true
			}
		}

	case TokenURI:
		//glog.Debugf("i=%d, r=%c, tokenStop=%t, tokenType=%s", i, r, this.state.tokenStop, this.state.tokenType)
		switch {
		case (i == 1 && (r == 't' || r == 'T')) ||
			(i == 2 && (r == 't' || r == 'T')) ||
			(i == 3 && (r == 'p' || r == 'P')) ||
			(i == 4 && (r == 's' || r == 'S')) ||
			((i == 4 || i == 5) && r == ':') ||
			((i == 5 || i == 6) && r == '/') ||
			((i == 6 || i == 7) && r == '/'):

			this.state.tokenType = TokenURI

		default:
			//if i >= 6 && (!unicode.IsSpace(r) || (this.state.inquote && matchQuote(this.state.chquote, r))) {
			if i >= 6 && isUrlChar(r) {
				// part of URL, keep going
				//this.state.tokenType = TokenURI
			} else if i == 4 && r == '/' {
				// if it's /, then it's probably something like http/1.0 or http/1.1,
				// let's keep it going
				this.state.tokenType = TokenLiteral
			} else if isLiteral(r) || (this.state.inquote && !matchQuote(this.state.chquote, r)) {
				// no longer URL, turn into literal
				this.state.tokenType = TokenLiteral
			} else {
				this.state.tokenStop = true

				// if there are 6 or less chars, then it can't be an URL, must be literal
				if i < 6 {
					this.state.tokenType = TokenLiteral
				}
			}
		}

	case TokenInteger:
		switch r {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			//this.state.tokenType = TokenInteger

		case '.':
			// this should be the ONLY dot this switch case should see
			this.state.dots++
			this.state.tokenType = TokenFloat

		default:
			if isLiteral(r) || (this.state.inquote && !matchQuote(this.state.chquote, r)) {
				// no longer URL, turn into literal
				this.state.tokenType = TokenLiteral
			} else {
				this.state.tokenStop = true
			}
		}

	case TokenFloat:
		switch r {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			//this.state.tokenType = TokenFloat

		case '.':
			this.state.dots++
			// this SHOULD only be the second dot we encountered...

			// If this token started with a dot, then it can't be ipv4,
			// must be literal
			if this.state.initDot {
				this.state.tokenType = TokenLiteral
			} else {
				// otherwise assume it's ipv4
				// FIXME: will consider something like "123.." as the beginning of IPv4
				this.state.tokenType = TokenIPv4
			}

		default:
			if isLiteral(r) || (this.state.inquote && !matchQuote(this.state.chquote, r)) {
				// no longer URL, turn into literal
				this.state.tokenType = TokenLiteral
			} else {
				this.state.tokenStop = true
			}
		}

	case TokenLiteral:
		if isLiteral(r) || (this.state.inquote && !matchQuote(this.state.chquote, r)) || (!this.state.inquote && r == '\'') {
			//this.state.tokenType = TokenLiteral
		} else {
			this.state.tokenStop = true
		}
		//glog.Debugf("tokenStop=%t, r=%c", this.state.tokenStop, r)

	case TokenIPv4:
		switch r {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			//this.state.tokenType = TokenFloat

		case '.':
			this.state.dots++
			// this SHOULD only be the second dot we encountered...

			// If this token started with a dot, then it can't be ipv4,
			// must be literal
			if this.state.initDot {
				this.state.tokenType = TokenLiteral
			} else {
				// otherwise assume it's ipv4
				this.state.tokenType = TokenIPv4
			}

		case '/':
			this.state.tokenStop = true

		default:
			if isLiteral(r) || (this.state.inquote && !matchQuote(this.state.chquote, r)) {
				// no longer URL, turn into literal
				this.state.tokenType = TokenLiteral
			} else {
				this.state.tokenStop = true
			}
		}
	}

	//glog.Debugf("2. i=%d, r=%c, tokenStop=%t, tokenType=%s", i, r, this.state.tokenStop, this.state.tokenType)

	return this.state.tokenStop
}

// hexStep steps through a string and try to match a hex string of the format
// - dead:beef:1234:5678:223:32ff:feb1:2e50 (ipv6 address)
// - de:ad:be:ef:74:a6:bb:45:45:52:71:de:b2:12:34:56 (mac address)
// - 0:09:36 (literal)
// - f0f0:f::1 (ipv6)
// - and a few others in the scanner_test.go/hextests list
//
// The ipv6 rules are:
// (http://computernetworkingnotes.com/ipv6-features-concepts-and-configurations/ipv6-address-types-and-formats.html)
// - Whereas IPv4 addresses use a dotted-decimal format, where each byte ranges from
//   0 to 255.
// - IPv6 addresses use eight sets of four hexadecimal addresses (16 bits in each set),
//   separated by a colon (:), like this: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
//   (x would be a hexadecimal value). This notation is commonly called string notation.
// - Hexadecimal values can be displayed in either lower- or upper-case for the numbers
//   A–F.
// - A leading zero in a set of numbers can be omitted; for example, you could either
//   enter 0012 or 12 in one of the eight tags—both are correct.
// - If you have successive tags of zeroes in an IPv6 address, you can represent
//   them as two colons (::). For example,0:0:0:0:0:0:0:5 could be represented as ::5;
//   and ABC:567:0:0:8888:9999:1111:0 could be represented asABC:567::8888:9999:1111:0.
//   However, you can only do this once in the address: ABC::567::891::00 would be
//   invalid since ::appears more than once in the address. The reason for this
//   limitation is that if you had two or more repetitions, you wouldn’t know how many
//   sets of zeroes were being omitted from each part. An unspecified address is
//   represented as ::, since it contains all zeroes.
//
// first return value indicates whether this is a valid hex string
// second return value indicates whether to stop scanning
func (this *Message) hexStep(i int, r rune) (bool, bool) {
	switch this.state.hexState {
	case hexStart:
		switch {
		case isHex(r):
			this.state.hexState = hexChar1

		case r == ':':
			this.state.hexState = hexColon
			this.state.hexColons++
			this.state.hexSuccColons++
			this.state.hexStart = true
			this.state.hexState = hexColon

			if this.state.hexSuccColons > this.state.hexMaxSuccColons {
				this.state.hexMaxSuccColons = this.state.hexSuccColons
			}

		default:
			return false, true
		}

		return false, false

	case hexColon:
		switch {
		case isHex(r):
			this.state.hexState = hexChar1
			this.state.hexSuccColons = 0

			if this.state.hexColons > 0 {
				return true, false
			}

		case r == ':':
			this.state.hexSuccColons++
			this.state.hexColons++

			if this.state.hexSuccColons == 2 {
				this.state.hexSuccColonsSeries++
			}

			if this.state.hexSuccColons > this.state.hexMaxSuccColons {
				this.state.hexMaxSuccColons = this.state.hexSuccColons
			}

			this.state.hexState = hexColon

			// for the special case of "::" which is valid and represents an
			// unspecified ip
			if i == 1 {
				return true, false
			}

		default:
			if this.state.hexColons > 0 && unicode.IsSpace(r) {
				return true, true
			}
			return false, true
		}

		return false, false

	case hexChar1, hexChar2, hexChar3, hexChar4:
		switch {
		case this.state.hexState != hexChar4 && isHex(r):
			this.state.hexState++
			this.state.hexSuccColons = 0

		case r == ':':
			this.state.hexState = hexColon
			this.state.hexColons++
			this.state.hexSuccColons++

			if this.state.hexSuccColons > this.state.hexMaxSuccColons {
				this.state.hexMaxSuccColons = this.state.hexSuccColons
			}

		default:
			if this.state.hexColons > 0 && unicode.IsSpace(r) {
				return true, true
			}
			return false, true
		}

		if this.state.hexColons > 0 {
			return true, false
		}

		return false, false
	}

	return false, true
}

func (this *Message) reset() {
	this.state.prevToken = Token{}
	this.state.inquote = false
	this.state.nxquote = true
	this.state.start = 0
	this.state.end = len(this.Data)
	this.state.cur = 0
	this.state.backslash = false

	this.resetTokenStates()
}

func (this *Message) resetTokenStates() {
	this.state.dots = 0
	this.state.tokenType = TokenUnknown
	this.state.tokenStop = false
	this.state.initDot = false

	this.resetHexStates()
}

func (this *Message) resetHexStates() {
	this.state.hexState = hexStart
	this.state.hexStart = false
	this.state.hexColons = 0
	this.state.hexSuccColons = 0
	this.state.hexMaxSuccColons = 0
	this.state.hexSuccColonsSeries = 0
}

func isLetter(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || r == '_' || r >= 0x80 && unicode.IsLetter(r)
}

func isLiteral(r rune) bool {
	//return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == '-' || r == '_' || r == '#' || r == '\\' || r == '%' || r == '*' || r == '@' || r == '$' || r == '?' || r == '.' || r == '&' || r == '/'
	switch r {
	case '+', '-', '_', '#', '\\', '%', '*', '@', '$', '?', '.', '&', '/':
		return true
	}
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || r >= '0' && r <= '9'
}

func isHex(r rune) bool {
	return isDigit(r) || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
}

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

// http://tools.ietf.org/html/rfc3986#section-2
func isUrlChar(r rune) bool {
	switch r {
	case '-', '.', '_', '~', ':', '/', '?', '#', '[', ']', '@', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', '%', '|':
		return true
	}
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || r >= '0' && r <= '9'
}

func isTagTokenChar(r rune) bool {
	switch r {
	case '+', '-', '*', ':', '_':
		return true
	}
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || r >= '0' && r <= '9'
}

// q - quote char in state
// r - current char
func matchQuote(q, r rune) bool {
	return (((r == '"' || r == '\'') && r == q) || (r == '>' && q == '<'))
}
