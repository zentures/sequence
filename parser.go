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
	rest, // absorb the rest of the string?
	parent bool // is this parent, or does this have child(ren)?

	// token types children
	tc [TokenTypesCount][]*parseNode

	// literal children
	lc map[string]*parseNode
}

type stackParseNode struct {
	node  *parseNode
	level int    // current level of the node
	score int    // the score of the path traversed
	value string // value of the token evaluated
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
	}
}

func (this *parseNode) String() string {
	return fmt.Sprintf("node=%s, leaf=%t, parent=%t, rest=%t", this.Token.String(), this.leaf, this.parent, this.rest)
}

// Add will add a single pattern sequence to the parser tree. This effectively
// builds the parser tree so it can be used for parsing later.
//func (this *Parser) Add(s string) error {
func (this *Parser) Add(seq Sequence) error {
	this.mu.Lock()
	defer this.mu.Unlock()

	cur := this.root

	for _, token := range seq {
		vl := len(token.Value)
		more, rest := false, false

		if vl >= 2 && token.Value[0] == '%' && token.Value[vl-1] == '%' {
			switch token.Value[vl-2] {
			case metaMore:
				token.Value = token.Value[:vl-2] + "%"
				more = true
			case metaRest:
				token.Value = token.Value[:vl-2] + "%"
				rest = true
			}

			if f := name2FieldType(token.Value); f != FieldUnknown {
				token.Field = f
				token.Type = f.TokenType()
			} else if t := name2TokenType(token.Value); t != TokenUnknown {
				token.Type = t
				token.Field = FieldUnknown
			}
		}

		var found *parseNode

		switch {
		case token.Type != TokenUnknown && token.Type != TokenLiteral:
			// token nodes
			if cur.tc[token.Type] != nil {
				for _, n := range cur.tc[token.Type] {
					if n.Type == token.Type && n.Field == token.Field {
						found = n
						break
					}
				}
			}

			if found == nil {
				found = newParseNode()
				found.Token = token
				cur.tc[token.Type] = append(cur.tc[token.Type], found)
				cur.parent = true
			}

			if more {
				found.tc[token.Type] = append(found.tc[token.Type], found)
				found.parent = true
			}

			if rest {
				found.rest = rest
			}

		case token.Type == TokenLiteral:
			var ok bool
			v := strings.ToLower(token.Value)
			if found, ok = cur.lc[v]; !ok {
				found = newParseNode()
				found.Token = token
				found.Value = v
				cur.lc[v] = found
				cur.parent = true
			}
		}

		//glog.Debugf("Added %s", found)
		cur = found
	}

	cur.leaf = true

	//fmt.Printf("parser.go/AddPattern(): count = %d, height = %d\n", msg.Count(), this.height)
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

	//glog.Debugln(seq.PrintTokens())

	var (
		cur stackParseNode

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
		toVisit, cur = toVisit[:len(toVisit)-1], toVisit[len(toVisit)-1]

		//glog.Debugf("cur=%s, len(seq)=%d", cur.String(), len(seq))

		// cur is the current token, if it's added to the list, that means it matched
		// the last token, which means it should be part of the path. If it's level 0,
		// or root level, don't add it.
		if cur.level > 0 {
			if len(path) < cur.level {
				path = append(path, Token{})
			}
			path = path[:cur.level]

			path[cur.level-1] = cur.node.Token
			path[cur.level-1].Value = cur.value
		}

		if cur.node.leaf {
			if cur.node.rest {
				l := len(path) - 1
				for i := cur.level; i < len(seq); i++ {
					path[l].Value += " " + seq[i].Value
				}
			}

			if cur.node.rest || len(seq) <= cur.level {
				// end of tokens, so let's finalize the current path. If the current
				// node is a leaf, that means we matched the sequence, so let's add it
				// to the path list.
				if cur.score > bestScore {
					bestScore = cur.score
					bestPath = append(bestPath[:0], path...)
				}

				continue
			}
		}

		// If there's not enough tokens extractd from the message, then let's get more.
		// Because we need to look at the next level, the length of the sequence must
		// be greater than the current level.
		var token Token

		if len(seq) > cur.level {
			token = seq[cur.level]
		} else {
			continue
		}

		//glog.Debugf("token=%q", token)

		switch token.Type {
		case TokenLiteral:
			for _, n := range cur.node.tc[TokenString] {
				toVisit = append(toVisit, stackParseNode{n, cur.level + 1, cur.score + partialMatchWeight, token.Value})
			}

			// If the values match, then it's a full match, add it to the stack
			if n, ok := cur.node.lc[token.Value]; ok {
				toVisit = append(toVisit, stackParseNode{n, cur.level + 1, cur.score + fullMatchWeight, token.Value})
			}

		default:
			for _, n := range cur.node.tc[token.Type] {
				toVisit = append(toVisit, stackParseNode{n, cur.level + 1, cur.score + fullMatchWeight, token.Value})
			}
		}
	}

	if bestScore > 0 {
		return bestPath, nil
	}

	return nil, ErrNoMatch
}
