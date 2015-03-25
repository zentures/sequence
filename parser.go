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
	"sync"
)

const (
	metaMinus = "-"
	metaPlus  = "+"
	metaStar  = "*"

	partialMatchWeight = 1
	fullMatchWeight    = 2
)

// Parser is a tree-based parsing engine for log messages. It builds a parsing tree
// based on pattern sequence supplied, and for each message sequence, returns the
// matching pattern sequence. Each of the message tokens will be marked with the
// semantic field types.
type Parser struct {
	root   *parseNode
	height int
	mu     sync.RWMutex
}

type parseNode struct {
	Token

	leaf, // is this a leaf?
	parent bool // is this parent, or does this have child(ren)?

	minus bool // absorb the rest of the string?

	// token types children
	tc [][]*parseNode

	// literal children
	lc map[string]*parseNode
}

type stackParseNode struct {
	node   *parseNode
	level  int    // current level of the node
	seqidx int    // current index of the sequence being parsed
	score  int    // the score of the path traversed
	value  string // value of the token evaluated
}

func (this stackParseNode) String() string {
	return fmt.Sprintf("level=%d, score=%d, %s", this.level, this.score, this.node)
}

func NewParser() *Parser {
	return &Parser{
		root:   newParseNode(),
		height: 0,
	}
}

func newParseNode() *parseNode {
	return &parseNode{
		lc: make(map[string]*parseNode),
		tc: make([][]*parseNode, TokenTypesCount),
	}
}

func (this *parseNode) String() string {
	return fmt.Sprintf("node=%s, leaf=%t, parent=%t, minus=%t", this.Token.String(), this.leaf, this.parent, this.minus)
}

// Add will add a single pattern sequence to the parser tree. This effectively
// builds the parser tree so it can be used for parsing later.
//func (this *Parser) Add(s string) error {
func (this *Parser) Add(seq Sequence) error {
	this.mu.Lock()
	defer this.mu.Unlock()

	parent := this.root
	var grandparent *parseNode = nil

	for _, token := range seq {
		vl := len(token.Value)
		//minus, plus, star := false, false, false

		if vl >= 2 && token.Value[0] == '%' && token.Value[vl-1] == '%' {
			var err error
			if token, err = processFieldToken(token); err != nil {
				return err
			}
		}

		//log.Printf("add token=%s", token)

		var found *parseNode

		switch {
		case token.Type != TokenUnknown && token.Type != TokenLiteral:
			// token nodes
			if parent.tc[token.Type] != nil {
				for _, n := range parent.tc[token.Type] {
					if n.Type == token.Type && n.Field == token.Field && n.until == token.until {
						found = n
						break
					}
				}
			}

			if found == nil {
				found = newParseNode()
				found.Token = token
				parent.tc[found.Type] = append(parent.tc[found.Type], found)
				parent.parent = true
			}

			if token.plus || token.star {
				found.tc[found.Type] = append(found.tc[found.Type], found)
				found.parent = true
			}

			found.minus, found.plus, found.star = token.minus, token.plus, token.star

		case token.Type == TokenLiteral:
			var ok bool
			v := strings.ToLower(token.Value)
			if found, ok = parent.lc[v]; !ok {
				found = newParseNode()
				found.Token = token
				found.Value = v
				found.until = strings.ToLower(token.until)
				parent.lc[v] = found
				parent.parent = true
			}
		}

		if grandparent != nil {
			var grandchild *parseNode = nil
			var ok = false

			switch {
			case found.Type != TokenUnknown && found.Type != TokenLiteral:
				if grandparent.tc[found.Type] != nil {
					for _, n := range grandparent.tc[found.Type] {
						if n.Type == found.Type && n.Field == found.Field {
							grandchild = n
							break
						}
					}
				}

				if grandchild == nil {
					grandparent.tc[found.Type] = append(grandparent.tc[found.Type], found)
					grandparent.parent = true
				}

			case found.Type == TokenLiteral:
				if grandchild, ok = grandparent.lc[found.Value]; !ok {
					grandparent.lc[found.Value] = found
					grandparent.parent = true
				}
			}

		}

		if found.star {
			grandparent = parent
		} else {
			grandparent = nil
		}

		parent = found
	}

	parent.leaf = true

	if grandparent != nil {
		grandparent.leaf = true
	}

	if len(seq) > this.height {
		this.height = len(seq) + 1
	}

	return nil
}

// Parse will take the message sequence supplied and go through the parser tree to
// find the matching pattern sequence. If found, the pattern sequence is returned.
//func (this *Parser) Parse(s string) (Sequence, error) {
func (this *Parser) Parse(seq Sequence) (Sequence, error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	for i, t := range seq {
		if t.Type == TokenLiteral {
			seq[i].Value = strings.ToLower(t.Value)
		}
	}

	var (
		parent stackParseNode

		// Keep track of the path we have walked
		path = make(Sequence, len(seq))

		bestScore int
		bestPath  = make(Sequence, len(seq))
	)

	// toVisit is a stack, children that need to be visited are appended to the end,
	// and we take children from the end to visit
	toVisit := append(make([]stackParseNode, 0, this.height), stackParseNode{node: this.root})

	for len(toVisit) > 0 {
		// pop the last element from the toVisit stack
		toVisit, parent = toVisit[:len(toVisit)-1], toVisit[len(toVisit)-1]

		// glog.Debugf("parent=%s, len(seq)=%d", parent.String(), len(seq))

		// parent is the current token, if it's added to the list, that means it matched
		// the last token, which means it should be part of the path. If it's level 0,
		// or root level, don't add it.
		if parent.level > 0 {
			if len(path) < parent.level {
				path = append(path, Token{})
			}
			path = path[:parent.level]

			l := parent.level - 1
			path[l] = parent.node.Token
			path[l].Value = parent.value

			if parent.node.until != "" {
				i := parent.seqidx
				for ; i < len(seq) && seq[i].Value != parent.node.until; i++ {
					path[l].Value += " " + seq[i].Value
				}

				parent.seqidx = i

				// Consumed all tokens, yet this is not a leaf, then wrong, continue
				if parent.seqidx == len(seq) && !parent.node.leaf {
					continue
				}
			}
		}

		if parent.node.leaf {
			if parent.node.minus {
				l := len(path) - 1
				i := parent.seqidx
				for ; i < len(seq); i++ {
					path[l].Value += " " + seq[i].Value
				}
				parent.seqidx = i
			}

			if len(seq) <= parent.seqidx {
				// end of tokens, so let's finalize the current path. If the current
				// node is a leaf, that means we matched the sequence, so let's add it
				// to the path list.
				if parent.score > bestScore {
					bestScore = parent.score
					bestPath = append(bestPath[:0], path...)
				}

				continue
			}
		}

		// If there's not enough tokens extractd from the message, then let's get more.
		// Because we need to look at the next level, the length of the sequence must
		// be greater than the current level.
		var token Token

		//if len(seq) > parent.level {
		if len(seq) > parent.seqidx {
			token = seq[parent.seqidx]
		} else {
			continue
		}

		// glog.Debugf("Checking token=%s", token)

		switch token.Type {
		case TokenLiteral:
			// Find any children that's a string token and add them to the stack
			// if len(token.Value) > 1 || (len(token.Value) == 1 && isLiteral(rune(token.Value[0]))) {
			for _, n := range parent.node.tc[TokenString] {
				toVisit = append(toVisit, stackParseNode{n, parent.level + 1, parent.seqidx + 1, parent.score + partialMatchWeight, token.Value})
			}
			// }

			// If the values match, then it's a full match, add it to the stack
			if n, ok := parent.node.lc[token.Value]; ok {
				toVisit = append(toVisit, stackParseNode{n, parent.level + 1, parent.seqidx + 1, parent.score + fullMatchWeight, token.Value})
			}

		default:
			for _, n := range parent.node.tc[token.Type] {
				toVisit = append(toVisit, stackParseNode{n, parent.level + 1, parent.seqidx + 1, parent.score + fullMatchWeight, token.Value})
			}
		}
	}

	if bestScore > 0 {
		l := len(bestPath)
		for i := 0; i < l; i++ {
			t := bestPath[i]
			if t.plus || t.star {
				var j int
				for j = i + 1; j < l && (bestPath[j].star || bestPath[j].plus) && t.Field == bestPath[j].Field && t.Type == bestPath[j].Type; j++ {
					t.Value += " " + bestPath[j].Value
				}
				bestPath[i] = t
				bestPath = append(bestPath[:i+1], bestPath[j:]...)
				l = len(bestPath)
			}
		}
		return bestPath, nil
	}

	return nil, ErrNoMatch
}

// A field token is of the format "%field:type:meta%".
// - field is the name of the field
// - type is the token type of the field
// - meta is one of the following meta characters -, +, *, where
//   - "-" means the rest of the tokens
//   - "+" means one or more of this token
//   - "*" means zero or more of this token
//
// Formats can be
// - %field%
// - %type%
// - %field:type%
// - %field:meta%
// - %type:meta%
// - %field:type:meta%
func processFieldToken(token Token) (Token, error) {
	parts := strings.Split(token.Value[1:len(token.Value)-1], ":")

	switch len(parts) {
	case 1:
		// If there's only 1 part, then it can only be %field% or %type%
		if token.Field = name2FieldType(parts[0]); token.Field == FieldUnknown {
			token.Type = name2TokenType(parts[0])
		} else {
			token.Type = token.Field.TokenType()
		}

		if token.Type == TokenUnknown {
			return token, fmt.Errorf("Invalid field token %q: unknown type", token.Value)
		}

	case 2:
		// If there are two parts, then it can be any of the following combination
		// - %field:type%
		// - %field:meta%
		// - %type:meta%
		// - %literal:until%

		meta := false

		// first part must be either field or type
		if token.Field = name2FieldType(parts[0]); token.Field == FieldUnknown {
			if token.Type = name2TokenType(parts[0]); token.Type == TokenUnknown {
				return token, fmt.Errorf("Invalid field token %q", token.Value)
			} else {
				meta = true
			}
		} else if token.Type = name2TokenType(parts[1]); token.Type == TokenUnknown {
			meta = true
			token.Type = token.Field.TokenType()
		}

		if meta {
			switch parts[1] {
			case metaPlus:
				token.plus = true
			case metaMinus:
				token.minus = true
			case metaStar:
				token.star = true
			default:
				return token, fmt.Errorf("Invalid field token %q: unknown meta character", token.Value)
			}
		}

	case 3:
		// %field:type:meta%
		// %field:-:until%

		if token.Field = name2FieldType(parts[0]); token.Field == FieldUnknown {
			return token, fmt.Errorf("Invalid field token %q", token.Value)
		}

		if parts[1] == metaMinus {
			token.minus = true
			token.Type = token.Field.TokenType()
			token.until = parts[2]
			return token, nil
		} else if parts[1] == "" {
			token.Type = token.Field.TokenType()
		} else if token.Type = name2TokenType(parts[1]); token.Type == TokenUnknown {
			return token, fmt.Errorf("Invalid parts token %q: unknown type", token.Value)
		}

		switch parts[2] {
		case metaPlus:
			token.plus = true
		case metaMinus:
			token.minus = true
		case metaStar:
			token.star = true
		default:
			return token, fmt.Errorf("Invalid field token %q: unknown meta character", token.Value)
		}

	default:
		return token, fmt.Errorf("Invalid parts token %q", token.Value)
	}

	return token, nil
}
