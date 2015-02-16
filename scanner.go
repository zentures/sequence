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

type Scanner interface {
	Tokenize(s string, seq Sequence) (Sequence, error)
}

// GeneralScanner is a sequential lexical analyzer that breaks a log message into a
// sequence of tokens. It is sequential because it goes through log message
// sequentially tokentizing each part of the message, without the use of regular
// expressions. The scanner currently recognizes time stamps, IPv4 addresses, URLs,
// MAC addresses, integers and floating point numbers.
type GeneralScanner struct {
}

var (
	_              Scanner = (*GeneralScanner)(nil)
	DefaultScanner         = &GeneralScanner{}
)

// Tokenize returns a Sequence, or a list of tokens, for the data string supplied.
// The returned Sequence is only valid until the next time Tokenize() is called.
//
// For example, the following message
//
//   Jan 12 06:49:42 irc sshd[7034]: Failed password for root from 218.161.81.238 port 4228 ssh2
//
// Returns the following Sequence:
//
// 	Sequence{
// 		Token{TokenTime, FieldUnknown, "Jan 12 06:49:42"},
// 		Token{TokenLiteral, FieldUnknown, "irc"},
// 		Token{TokenLiteral, FieldUnknown, "sshd"},
// 		Token{TokenLiteral, FieldUnknown, "["},
// 		Token{TokenInteger, FieldUnknown, "7034"},
// 		Token{TokenLiteral, FieldUnknown, "]"},
// 		Token{TokenLiteral, FieldUnknown, ":"},
// 		Token{TokenLiteral, FieldUnknown, "Failed"},
// 		Token{TokenLiteral, FieldUnknown, "password"},
// 		Token{TokenLiteral, FieldUnknown, "for"},
// 		Token{TokenLiteral, FieldUnknown, "root"},
// 		Token{TokenLiteral, FieldUnknown, "from"},
// 		Token{TokenIPv4, FieldUnknown, "218.161.81.238"},
// 		Token{TokenLiteral, FieldUnknown, "port"},
// 		Token{TokenInteger, FieldUnknown, "4228"},
// 		Token{TokenLiteral, FieldUnknown, "ssh2"},
// 	},
//
// The following message
//
//   id=firewall time="2005-03-18 14:01:43" fw=TOPSEC priv=4 recorder=kernel type=conn policy=504 proto=TCP rule=deny src=210.82.121.91 sport=4958 dst=61.229.37.85 dport=23124 smac=00:0b:5f:b2:1d:80 dmac=00:04:c1:8b:d8:82
//
// Will return
// 	Sequence{
// 		Token{TokenLiteral, FieldUnknown, "id"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenLiteral, FieldUnknown, "firewall"},
// 		Token{TokenLiteral, FieldUnknown, "time"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenLiteral, FieldUnknown, "\""},
// 		Token{TokenTime, FieldUnknown, "2005-03-18 14:01:43"},
// 		Token{TokenLiteral, FieldUnknown, "\""},
// 		Token{TokenLiteral, FieldUnknown, "fw"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenLiteral, FieldUnknown, "TOPSEC"},
// 		Token{TokenLiteral, FieldUnknown, "priv"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenInteger, FieldUnknown, "4"},
// 		Token{TokenLiteral, FieldUnknown, "recorder"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenLiteral, FieldUnknown, "kernel"},
// 		Token{TokenLiteral, FieldUnknown, "type"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenLiteral, FieldUnknown, "conn"},
// 		Token{TokenLiteral, FieldUnknown, "policy"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenInteger, FieldUnknown, "504"},
// 		Token{TokenLiteral, FieldUnknown, "proto"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenLiteral, FieldUnknown, "TCP"},
// 		Token{TokenLiteral, FieldUnknown, "rule"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenLiteral, FieldUnknown, "deny"},
// 		Token{TokenLiteral, FieldUnknown, "src"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenIPv4, FieldUnknown, "210.82.121.91"},
// 		Token{TokenLiteral, FieldUnknown, "sport"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenInteger, FieldUnknown, "4958"},
// 		Token{TokenLiteral, FieldUnknown, "dst"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenIPv4, FieldUnknown, "61.229.37.85"},
// 		Token{TokenLiteral, FieldUnknown, "dport"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenInteger, FieldUnknown, "23124"},
// 		Token{TokenLiteral, FieldUnknown, "smac"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenMac, FieldUnknown, "00:0b:5f:b2:1d:80"},
// 		Token{TokenLiteral, FieldUnknown, "dmac"},
// 		Token{TokenLiteral, FieldUnknown, "="},
// 		Token{TokenMac, FieldUnknown, "00:04:c1:8b:d8:82"},
// 	}
func (this *GeneralScanner) Tokenize(s string, seq Sequence) (Sequence, error) {
	msg := &message{
		data: s,
	}

	msg.reset()

	var (
		err error
		tok Token
	)

	for tok, err = msg.scan(); err == nil; tok, err = msg.scan() {
		// For some reason this is consistently slightly faster than just append
		if len(seq) >= cap(seq) {
			seq = append(seq, tok)
		} else {
			i := len(seq)
			seq = seq[:i+1]
			seq[i].Field = tok.Field
			seq[i].Type = tok.Type
			seq[i].Value = tok.Value
			seq[i].isKey, seq[i].isValue = false, false
		}
	}

	if err != nil && err != io.EOF {
		return nil, err
	}

	return seq, nil
}

type message struct {
	data string

	state struct {
		// these are per token states
		tokenType TokenType
		tokenStop bool
		dots      int

		// these are per message states
		prevToken Token
		tokCount  int

		// Are we inside a quote such as ", ', <, [
		inquote bool

		// Which quote character is it?
		chquote rune

		// Should the next quote be an open quote?
		// See special case in scan()
		nxquote bool

		// cursor positions
		cur, start, end int

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
func (this *message) scan() (Token, error) {
	if this.state.start < this.state.end {
		// Number of spaces skipped
		nss := this.skipSpace(this.data[this.state.start:])
		this.state.start += nss

		l, t, err := this.scanToken(this.data[this.state.start:])
		if err != nil {
			return Token{}, err
		} else if l == 0 {
			return Token{}, io.EOF
		} else if t == TokenUnknown {
			return Token{}, fmt.Errorf("unknown token encountered: %s\n%v", this.data[this.state.start:], t)
		}

		// remove any trailing spaces
		s := 0 // trail space count
		for this.data[this.state.start+l-1] == ' ' && l > 0 {
			l--
			s++
		}

		// For the special case of
		// "9.26.157.44 - - [16/Jan/2003:21:22:59 -0500] "GET http://WSsamples HTTP/1.1" 301 315"
		// where we want to parse the stuff inside the quotes
		if l == 1 && this.state.inquote == true && this.state.tokCount == 6 && this.state.prevToken.Value == "]" && this.data[this.state.start:this.state.start+l] == "\"" {
			this.state.inquote = false
			this.state.nxquote = false
		}

		tok := Token{Field: FieldUnknown, Type: t, Value: this.data[this.state.start : this.state.start+l]}
		this.state.tokCount++
		this.state.prevToken = tok
		this.state.start += l + s

		return tok, nil
	}

	return Token{}, io.EOF
}

func (this *message) skipSpace(data string) int {
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

func (this *message) scanToken(data string) (int, TokenType, error) {
	var (
		tnode                       *timeNode = timeFsmRoot
		timeStop, hexStop, hexValid bool
		timeLen, hexLen, tokenLen   int
		l                           = len(data)
	)

	this.state.dots = 0
	this.state.tokenType = TokenUnknown
	this.state.tokenStop = false
	this.resetHexStates()

	// short circuit the time check
	if l < 3 {
		hexStop = true
	}

	// short circuit the time check
	if l < minTimeLength {
		timeStop = true
	}

	for i, r := range data {
		if !this.state.tokenStop {
			this.tokenStep(i, r)

			if !this.state.tokenStop {
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

		//glog.Debugf("i=%d, r=%c, tokenStop=%t, timeStop=%t, hexStop=%t", i, r, this.state.tokenStop, timeStop, hexStop)
		// This means either we found something, or we have exhausted the string
		if (this.state.tokenStop && timeStop && hexStop) || i == l-1 {
			if timeLen > 0 {
				return timeLen, TokenTime, nil
			} else if hexValid && this.state.hexColons > 1 {
				if this.state.hexColons == 5 && this.state.hexMaxSuccColons == 1 {
					return hexLen, TokenMac, nil
				} else if this.state.hexSuccColonsSeries == 1 ||
					(this.state.hexColons == 7 && this.state.hexSuccColonsSeries == 0) {

					return hexLen, TokenIPv6, nil
				} else {
					return hexLen, TokenLiteral, nil
				}
			}

			// If token length is 0, it means we didn't find time, nor did we find
			// a word, it cannot be space since we skipped all space. This means it
			// is a single character literal, so return that.
			if tokenLen == 0 {
				return 1, TokenLiteral, nil
			} else {
				return tokenLen, this.state.tokenType, nil
			}
		}
	}

	return len(data), this.state.tokenType, nil
}

func (this *message) tokenStep(index int, r rune) {
	switch {
	case this.state.tokenType == TokenURL:
		if (index == 1 && (r == 't' || r == 'T')) ||
			(index == 2 && (r == 't' || r == 'T')) ||
			(index == 3 && (r == 'p' || r == 'P')) ||
			(index == 4 && (r == 's' || r == 'S')) ||
			((index == 4 || index == 5) && r == ':') ||
			((index == 5 || index == 6) && r == '/') ||
			((index == 6 || index == 7) && r == '/') ||
			(index >= 6 && !unicode.IsSpace(r)) {

			this.state.tokenType = TokenURL
		} else if isLiteral(r) {
			this.state.tokenType = TokenLiteral
		} else {
			// if there are 6 or less chars, then it can't be an URL, must be literal
			if index < 6 {
				this.state.tokenType = TokenLiteral
			}

			// if it's /, then it's probably something like http/1.0 or http/1.1,
			// let's keep it going
			if r != '/' {
				this.state.tokenStop = true
			}
		}

	case index == 0 && (r == 'h' || r == 'H'):
		this.state.tokenType = TokenURL

	case isLiteral(r):
		this.state.tokenType = TokenLiteral

	case r == '/':
		if this.state.tokenType == TokenIPv4 {
			this.state.tokenStop = true
		} else if this.state.prevToken.Type == TokenIPv4 {
			this.state.tokenType = TokenLiteral
			this.state.tokenStop = true
		} else {
			this.state.tokenType = TokenLiteral
		}

	case r >= '0' && r <= '9':
		if this.state.tokenType == TokenInteger || index == 0 {
			this.state.tokenType = TokenInteger
		} else if this.state.tokenType == TokenIPv4 && this.state.dots < 4 {
			this.state.tokenType = TokenIPv4
		} else if this.state.tokenType == TokenFloat && this.state.dots == 1 {
			this.state.tokenType = TokenFloat
		} else {
			this.state.tokenType = TokenLiteral
		}

	case r == '.':
		this.state.dots++

		if this.state.tokenType == TokenInteger && this.state.dots == 1 {
			this.state.tokenType = TokenFloat
		} else if (this.state.dots > 1 && this.state.tokenType == TokenFloat) ||
			(this.state.dots < 4 && this.state.tokenType == TokenIPv4) {

			this.state.tokenType = TokenIPv4
		} else {
			this.state.tokenType = TokenLiteral
		}

	case r == '"':
		this.state.tokenStop = true

		if index == 0 {
			if this.state.inquote == false && this.state.nxquote {
				// If we are not inside a quote now and we are at the beginning,
				// then let's be inside the quote now. This is basically the
				// beginning quotation mark.
				this.state.inquote = true
				this.state.chquote = r
			} else if this.state.inquote == true && this.state.chquote == '"' {
				// If we are at the beginning of the data and we are inside q quote,
				// then this is the ending quotation mark.
				this.state.inquote = false
			}
		}

	case r == '\'':
		if index == 0 && this.state.inquote == false {
			// If we are not inside a quote now and we are at the beginning,
			// then let's be inside the quote now. This is basically the
			// beginning quotation mark.
			this.state.inquote = true
			this.state.chquote = r
			this.state.tokenStop = true
		} else if index != 0 && this.state.inquote == true && this.state.chquote == '\'' {
			// If we are not at the beginning of the data and we are inside a quote,
			// then this is probably the end of the quote, so let's stop here.
			// What we capture is what's in between quotation marks.
			this.state.tokenStop = true
		} else if index == 0 && this.state.inquote == true && this.state.chquote == '\'' {
			// If we are at the beginning of the data and we are inside q quote,
			// then this is the ending quotation mark.
			this.state.inquote = false
			this.state.tokenStop = true
		} else {
			// Otherwise this is just part of the string literal
			this.state.tokenType = TokenLiteral
		}

	case r == '<':
		if this.state.inquote == false {
			if index == 0 {
				// If we are not inside a quote now then let's be inside the quote now.
				// This is basically the beginning quotation mark.
				this.state.inquote = true
				this.state.chquote = r
				this.state.tokenStop = true
			} else {
				this.state.tokenStop = true
			}
		} else {
			// Otherwise this is just part of the string literal
			this.state.tokenType = TokenLiteral
		}

	case r == '>':
		if this.state.inquote == true && this.state.chquote == '<' {
			if index == 0 {
				// If we are at the beginning of the data and we are inside q quote,
				// then this is the ending quotation mark.
				this.state.inquote = false
				this.state.tokenStop = true
			} else {
				// If we are not at the beginning of the data and we are inside a quote,
				// then this is probably the end of the quote, so let's stop here.
				// What we capture is what's in between quotation marks.
				this.state.tokenStop = true
			}
		} else {
			// Otherwise this is just part of the string literal
			this.state.tokenType = TokenLiteral
		}

	// case r == '[':
	// 	if this.state.inquote == false {
	// 		if index == 0 {
	// 			// If we are not inside a quote now then let's be inside the quote now.
	// 			// This is basically the beginning quotation mark.
	// 			this.state.inquote = true
	// 			this.state.chquote = r
	// 			this.state.tokenStop = true
	// 		} else {
	// 			this.state.tokenStop = true
	// 		}
	// 	} else {
	// 		// Otherwise this is just part of the string literal
	// 		this.state.tokenType = TokenLiteral
	// 	}

	// case r == ']':
	// 	if this.state.inquote == true && this.state.chquote == '[' {
	// 		if index == 0 {
	// 			// If we are at the beginning of the data and we are inside q quote,
	// 			// then this is the ending quotation mark.
	// 			this.state.inquote = false
	// 			this.state.tokenStop = true
	// 		} else {
	// 			// If we are not at the beginning of the data and we are inside a quote,
	// 			// then this is probably the end of the quote, so let's stop here.
	// 			// What we capture is what's in between quotation marks.
	// 			this.state.tokenStop = true
	// 		}
	// 	} else {
	// 		// Otherwise this is just part of the string literal
	// 		this.state.tokenType = TokenLiteral
	// 	}

	default:
		if !this.state.inquote {
			this.state.tokenStop = true
		}
	}

	if this.state.tokenStop {
		if (this.state.tokenType == TokenIPv4 && this.state.dots != 3) ||
			(this.state.tokenType == TokenFloat && this.state.dots != 1) {

			this.state.tokenType = TokenLiteral
		}
	}
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
//   enter 0012 or 12 in one of the eight fields—both are correct.
// - If you have successive fields of zeroes in an IPv6 address, you can represent
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
func (this *message) hexStep(i int, r rune) (bool, bool) {
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

func (this *message) reset() {
	this.state.tokenType = TokenUnknown
	this.state.tokenStop = false
	this.state.dots = 0
	this.state.prevToken = Token{}
	this.state.inquote = false
	this.state.nxquote = true
	this.state.start = 0
	this.state.end = len(this.data)
	this.state.cur = 0

	this.resetHexStates()
}

func (this *message) resetHexStates() {
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
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '+' || r == '-' || r == '_' || r == '#' || r == '\\' || r == '%' || r == '*' || r == '@' || r == '$' || r == '?'
}

func isHex(r rune) bool {
	return r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'
}
