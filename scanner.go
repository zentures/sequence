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
	"strconv"
)

// Scanner is a sequential lexical analyzer that breaks a log message into a
// sequence of tokens. It is sequential because it goes through log message
// sequentially tokentizing each part of the message, without the use of regular
// expressions. The scanner currently recognizes time stamps, IPv4 addresses, URLs,
// MAC addresses, integers and floating point numbers.
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
type Scanner struct {
	seq Sequence
	msg *Message
}

func NewScanner() *Scanner {
	return &Scanner{
		seq: make(Sequence, 0, 20),
		msg: &Message{},
	}
}

// Scan returns a Sequence, or a list of tokens, for the data string supplied.
// Scan is not concurrent-safe, and the returned Sequence is only valid until
// the next time any Scan*() method is called. The best practice would be to
// create one Scanner for each goroutine.
func (this *Scanner) Scan(s string) (Sequence, error) {
	this.msg.Data = s
	this.msg.reset()
	this.seq = this.seq[:0]

	var (
		err error
		tok Token
	)

	for tok, err = this.msg.Tokenize(); err == nil; tok, err = this.msg.Tokenize() {
		this.insertToken(tok)

		// special case for %r, or request, token in apache logs, which is comprised
		// of method, url, and protocol like "GET http://blah HTTP/1.0"
		if len(tok.Value) == 1 && tok.Value == "\"" && this.msg.state.inquote && this.msg.state.start != len(s) && s[this.msg.state.start] != ' ' {
			l := matchRequestMethods(s[this.msg.state.start:])
			if l > 0 {
				this.insertToken(Token{
					Field: FieldUnknown,
					Type:  TokenLiteral,
					Value: s[this.msg.state.start : this.msg.state.start+l],
				})

				this.msg.state.inquote = false
				this.msg.state.nxquote = false
				this.msg.state.start += l
			}
		}
	}

	if err != nil && err != io.EOF {
		return nil, err
	}

	return this.seq, nil
}

const (
	jsonStart = iota
	jsonObjectStart
	jsonObjectKey
	jsonObjectColon
	jsonObjectValue
	jsonObjectEnd
	jsonArrayStart
	jsonArrayValue
	jsonArraySeparator
	jsonArrayEnd
)

// ScanJson returns a Sequence, or a list of tokens, for the json string supplied.
// Scan is not concurrent-safe, and the returned Sequence is only valid until the
// next time any Scan*() method is called. The best practice would be to create
// one Scanner for each goroutine.
//
// ScanJson flattens a json string into key=value pairs, and it performs the
// following transformation:
//   - all {, }, [, ], ", characters are removed
//   - colon between key and value are changed to "="
//   - nested objects have their keys concatenated with ".", so a json string like
//   		"userIdentity": {"type": "IAMUser"}
//     will be returned as
//   		userIdentity.type=IAMUser
//   - arrays are flattened by appending an index number to the end of the key,
//     starting with 0, so a json string like
//   		{"value":[{"open":"2014-08-16T13:00:00.000+0000"}]}
//     will be returned as
//   		value.0.open = 2014-08-16T13:00:00.000+0000
//   - skips any key that has an empty value, so json strings like
//   		"reference":""		or		"filterSet": {}
//     will not show up in the Sequence
func (this *Scanner) ScanJson(s string) (Sequence, error) {
	this.msg.Data = s
	this.msg.reset()
	this.seq = this.seq[:0]

	var (
		err error
		tok Token

		keys = make([]string, 0, 20) // collection keys
		arrs = make([]int64, 0, 20)  // array index

		state          = jsonStart // state
		kquote, vquote bool        // quoted key, quoted value
	)

	for tok, err = this.msg.Tokenize(); err == nil; tok, err = this.msg.Tokenize() {
		// glog.Debugf("1. tok=%s, state=%d, kquote=%t, vquote=%t, depth=%d", tok, state, kquote, vquote, len(keys))
		// glog.Debugln(keys)
		// glog.Debugln(arrs)

		switch state {
		case jsonStart:
			switch tok.Value {
			case "{":
				state = jsonObjectStart
				keys = append(keys, "")

			default:
				return nil, fmt.Errorf("Invalid message. Expecting \"{\", got %q.", tok.Value)
			}

		case jsonObjectStart:
			switch tok.Value {
			case "{":
				// Only reason this could happen is if we encountered an array of
				// objects like [{"a":1}, {"b":2}]
				arrs[len(arrs)-1]++
				keys[len(keys)-1] = keys[len(keys)-2] + "." + strconv.FormatInt(arrs[len(arrs)-1], 10)
				keys = append(keys, "")

			case "\"":
				// start quote, ignore, move on
				//state = jsonObjectStart
				if kquote = !kquote; !kquote {
					return nil, fmt.Errorf("Invalid message. Expecting start quote for key, got end quote.")
				}

			case "}":
				// got something like {}, ignore this key
				if len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Too many } characters.")
				}

				keys = keys[:len(keys)-1]
				state = jsonObjectEnd

			default:
				if tok.Type == TokenLiteral {
					//glog.Debugf("depth=%d, keys=%v", len(keys), keys)
					switch len(keys) {
					case 0:
						return nil, fmt.Errorf("Invalid message. Expecting inside object, not so.")

					case 1:
						keys[0] = tok.Value

					default:
						keys[len(keys)-1] = keys[len(keys)-2] + "." + tok.Value
					}

					tok.Value = keys[len(keys)-1]
					tok.isKey = true
					this.insertToken(tok)
					state = jsonObjectKey

				} else {
					return nil, fmt.Errorf("Invalid message. Expecting string key, got %q.", tok.Value)
				}
			}

		case jsonObjectKey:
			switch tok.Value {
			case "\"":
				// end quote, ignore, move on
				//state = jsonObjectKey
				if kquote = !kquote; kquote {
					return nil, fmt.Errorf("Invalid message. Expecting end quote for key, got start quote.")
				}

			case ":":
				if kquote {
					return nil, fmt.Errorf("Invalid message. Expecting end quote for key, got %q.", tok.Value)
				}

				tok.Value = "="
				this.insertToken(tok)
				state = jsonObjectColon

			default:
				return nil, fmt.Errorf("Invalid message. Expecting colon or quote, got %q.", tok.Value)
			}

		case jsonObjectColon:
			switch tok.Value {
			case "\"":
				if vquote {
					// if vquote is already true, that means we encountered something like ""
					vquote = false

					// let's remove the key and "="
					if len(this.seq) >= 2 {
						this.seq = this.seq[:len(this.seq)-2]
					}

					state = jsonObjectValue
				} else {
					// start quote, ignore, move on
					vquote = true
				}

			case "[":
				// Start of an array
				state = jsonArrayStart
				arrs = append(arrs, 0)
				keys = append(keys, keys[len(keys)-1]+"."+strconv.FormatInt(arrs[len(arrs)-1], 10))

				// let's remove the key and "="
				if len(this.seq) >= 2 {
					this.seq = this.seq[:len(this.seq)-2]
				}

			case "{":
				state = jsonObjectStart
				keys = append(keys, "")

				if len(this.seq) >= 2 {
					this.seq = this.seq[:len(this.seq)-2]
				}

			default:
				state = jsonObjectValue
				tok.isValue = true
				this.insertToken(tok)
			}

		case jsonObjectValue:
			switch tok.Value {
			case "\"":
				// end quote, ignore, move on
				//state = jsonObjectKey
				if vquote = !vquote; vquote {
					return nil, fmt.Errorf("Invalid message. Expecting end quote for value, got start quote.")
				}

			case "}":
				// End of an object
				if len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Too many } characters.")
				}

				keys = keys[:len(keys)-1]
				state = jsonObjectEnd

			case ",":
				state = jsonObjectStart

			default:
				return nil, fmt.Errorf("Invalid message. Expecting '}', ',' or '\"', got %q.", tok.Value)
			}

		case jsonObjectEnd, jsonArrayEnd:
			switch tok.Value {
			case "}":
				// End of an object
				if len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Too many } characters.")
				}

				keys = keys[:len(keys)-1]
				state = jsonObjectEnd

			case "]":
				// End of an object
				if len(arrs)-1 < 0 || len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Mismatched ']' or '}' characters.")
				}

				keys = keys[:len(keys)-1]
				arrs = arrs[:len(arrs)-1]
				state = jsonArrayEnd

			case ",":
				state = jsonObjectStart
				// state = jsonArraySeparator
				// arrs[len(arrs)-1]++
				// keys[len(keys)-2] = keys[len(keys)-3] + "." + strconv.FormatInt(arrs[len(arrs)-1], 10)

			default:
				return nil, fmt.Errorf("Invalid message. Expecting '}' or ',', got %q.", tok.Value)
			}

		case jsonArraySeparator:
			switch tok.Value {
			case "{":
				state = jsonObjectStart
				keys = append(keys, "")

			default:
				return nil, fmt.Errorf("Invalid message. Expecting '{', got %q.", tok.Value)
			}

		case jsonArrayStart:
			switch tok.Value {
			case "\"":
				// start quote, ignore, move on
				//state = jsonArrayStart
				if kquote = !kquote; !kquote {
					return nil, fmt.Errorf("Invalid message. Expecting start quote for value, got end quote.")
				}

			case "{":
				state = jsonObjectStart
				keys = append(keys, "")

			default:
				if tok.Type == TokenLiteral {
					//glog.Debugf("depth=%d, keys=%v", depth, keys)
					this.insertToken(Token{
						Field:   FieldUnknown,
						Type:    TokenLiteral,
						Value:   keys[len(keys)-1],
						isKey:   true,
						isValue: false,
					})

					this.insertToken(Token{
						Field:   FieldUnknown,
						Type:    TokenLiteral,
						Value:   "=",
						isKey:   false,
						isValue: false,
					})

					tok.Value = keys[len(keys)-1]
					tok.isValue = true
					this.insertToken(tok)
					state = jsonArrayValue

				} else {
					return nil, fmt.Errorf("Invalid message. Expecting string key, got %q.", tok.Value)
				}
			}

		case jsonArrayValue:
			switch tok.Value {
			case "\"":
				// end quote, ignore, move on
				//state = jsonObjectKey
				if vquote = !vquote; vquote {
					return nil, fmt.Errorf("Invalid message. Expecting end quote for value, got start quote.")
				}

			case "]":
				// End of an object
				if len(arrs)-1 < 0 || len(keys)-1 < 0 {
					return nil, fmt.Errorf("Invalid message. Mismatched ']' or '}' characters.")
				}

				keys = keys[:len(keys)-1]
				arrs = arrs[:len(arrs)-1]
				state = jsonArrayEnd

			case ",":
				state = jsonArrayStart
				arrs[len(arrs)-1]++
				keys[len(keys)-1] = keys[len(keys)-2] + "." + strconv.FormatInt(arrs[len(arrs)-1], 10)

			default:
				return nil, fmt.Errorf("Invalid message. Expecting ']', ',' or '\"', got %q.", tok.Value)
			}
		}
		//glog.Debugf("2. tok=%s, state=%d, kquote=%t, vquote=%t, depth=%d", tok, state, kquote, vquote, len(keys))
	}

	if err != nil && err != io.EOF {
		return nil, err
	}

	return this.seq, nil
}

func (this *Scanner) insertToken(tok Token) {
	// For some reason this is consistently slightly faster than just append
	if len(this.seq) >= cap(this.seq) {
		this.seq = append(this.seq, tok)
	} else {
		i := len(this.seq)
		this.seq = this.seq[:i+1]
		this.seq[i] = tok
	}
}
