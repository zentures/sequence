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
	"io"
	"unicode"
)

var (
	ErrNegativeAdvance = errors.New("sequence: negative advance count")
	ErrAdvanceTooFar   = errors.New("sequence: advance count beyond input")
	ErrUnknownToken    = errors.New("sequence: unknown token encountered")
	ErrNoMatch         = errors.New("sequence: no pattern matched for this message")
	ErrInvalidCount    = errors.New("sequence: invalid count for field token")
)

// Message is a sequential lexical analyzer that breaks a log message into a sequence
// of tokens. It is sequential because it goes through log message sequentially
// tokentizing each part of the message, without the use of regular expressions.
// The scanner currently recognizes time stamps, IPv4 addresses, URLs, MAC addresses,
// integers and floating point numbers.
type Message struct {
	data   string
	tokens Sequence

	state struct {
		// these are per token states
		tokenType TokenType
		tokenStop bool
		dots      int

		// these are per message states
		prevToken Token

		// Are we inside a quote such as ", ', <, [
		inquote bool

		// Which quote character is it?
		chquote rune

		// Should the next quote be an open quote?
		// See special case in scan()
		nxquote bool

		// cursor positions
		cur, start, end int

		// should the next token be a value?
		nextisValue bool

		// how far from the = is the value, immediate following is 0
		valueDistance int
	}
}

func (this *Message) SetData(s string) {
	this.data = s

	// Reset the message states
	this.reset()
}

// Tokenize returns a Sequence, or a list of tokens, for the data string supplied.
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
func (this *Message) Tokenize(s string) (Sequence, error) {
	this.SetData(s)

	var err error

	for _, err = this.Scan(); err == nil; _, err = this.Scan() {
	}

	if err != nil && err != io.EOF {
		return nil, err
	}

	return this.tokens, nil
}

func (this *Message) Sequence() Sequence {
	return this.tokens
}

// Scan is similar to Tokenize except it returns one token at a time
func (this *Message) Scan() (Token, error) {
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
		for this.data[this.state.start+l-1] == ' ' && l > 0 {
			l--
		}

		v := this.data[this.state.start : this.state.start+l]
		this.state.start += l

		token := Token{Type: t, Value: v, Field: FieldUnknown}

		// For the special case of
		// "9.26.157.44 - - [16/Jan/2003:21:22:59 -0500] "GET http://WSsamples HTTP/1.1" 301 315"
		// where we want to parse the stuff inside the quotes
		if v == "\"" && this.state.inquote == true && len(this.tokens) == 6 && this.state.prevToken.Value == "]" {
			this.state.inquote = false
			this.state.nxquote = false
		}

		this.tokens = append(this.tokens, token)
		this.state.prevToken = token

		return token, nil
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
		tnode                      *timeNode = timeFsmRoot
		timeStop, macStop, macType bool
		timeLen, tokenLen          int
	)

	this.state.dots = 0
	this.state.tokenType = TokenUnknown
	this.state.tokenStop = false

	// short circuit the mac check
	// positions 2,5,8,11,14 must be ':'
	if len(data) < 17 || data[2] != ':' || data[14] != ':' {
		macStop = true
		macType = false
	}

	// short circuit the time check
	if len(data) < minTimeLength {
		timeStop = true
	}

	for i, r := range data {
		if !this.state.tokenStop {
			this.tokenStep(i, r)

			if !this.state.tokenStop {
				tokenLen++
			}
		}

		if !macStop {
			macType, macStop = this.macStep(i, r)

			if macType && macStop {
				return i + 1, TokenMac, nil
			}
		}

		if !timeStop {
			if tnode = timeStep(r, tnode); tnode == nil {
				timeStop = true

				if timeLen > 0 {
					return timeLen, TokenTime, nil
				}
			} else if tnode.final != TokenUnknown {
				if i+1 > timeLen {
					timeLen = i + 1
				}
			}
		}

		if this.state.tokenStop && timeStop && macStop {
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

func (this *Message) tokenStep(index int, r rune) {
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

// Returns bool, bool, first one is true if the it's a mac type, second is whether to stop scanning
func (this *Message) macStep(index int, r rune) (bool, bool) {
	switch {
	case index == 0 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 1 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 2 && r == ':':
		return true, false

	case index == 3 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 4 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 5 && r == ':':
		return true, false

	case index == 6 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 7 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 8 && r == ':':
		return true, false

	case index == 9 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 10 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 11 && r == ':':
		return true, false

	case index == 12 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 13 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 14 && r == ':':
		return true, false

	case index == 15 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, false

	case index == 16 && (r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r >= '0' && r <= '9'):
		return true, true
	}

	return false, true
}

func (this *Message) reset() {
	this.tokens = make(Sequence, 0, 20)
	this.state.tokenType = TokenUnknown
	this.state.tokenStop = false
	this.state.dots = 0
	this.state.prevToken = Token{}
	this.state.inquote = false
	this.state.nxquote = true
	this.state.start = 0
	this.state.end = len(this.data)
	this.state.cur = 0
}

func isLetter(ch rune) bool {
	return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || ch == '_' || ch >= 0x80 && unicode.IsLetter(ch)
}

func isLiteral(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '+' || r == '-' || r == '_' || r == '#' || r == '\\' || r == '%' || r == '*' || r == '@' || r == '$' || r == '?'
}
