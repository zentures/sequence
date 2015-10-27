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

import "strings"

type timeNode struct {
	ntype    int
	value    rune
	final    TokenType
	subtype  int
	children []*timeNode
}

const (
	timeNodeRoot = iota
	timeNodeLeaf
	timeNodeDigit
	timeNodeLetter
	timeNodeLiteral
	timeNodeSpace
	timeNodeDigitOrSpace
	timeNodePlusOrMinus
)

var (
	timeFsmRoot   *timeNode
	minTimeLength int = 1000
)

func buildTimeFSM(fmts []string) *timeNode {
	root := &timeNode{ntype: timeNodeRoot}

	for i, f := range fmts {
		f = strings.ToLower(f)
		if len(f) < minTimeLength {
			minTimeLength = len(f)
		}

		parent := root

		for _, r := range f {
			t := tnType(r)

			hasChild := false
			var child *timeNode

			for _, child = range parent.children {
				if (child.ntype == t && (t != timeNodeLiteral || (t == timeNodeLiteral && child.value == r))) ||
					(child.ntype == timeNodeDigitOrSpace && (t == timeNodeDigit || t == timeNodeSpace)) {
					hasChild = true
					break
				} else if child.ntype == timeNodeDigit && t == timeNodeDigitOrSpace {
					child.ntype = timeNodeDigitOrSpace
					hasChild = true
					break
				}
			}

			if !hasChild {
				child = &timeNode{ntype: t, value: r}
				parent.children = append(parent.children, child)
			}

			parent = child
		}

		parent.final = TokenTime
		parent.subtype = i
	}

	return root
}

func tnType(r rune) int {
	switch {
	case r >= '0' && r <= '9':
		return timeNodeDigit
	case r >= 'a' && r <= 'y' || r >= 'A' && r <= 'Y':
		return timeNodeLetter
	case r == ' ':
		return timeNodeSpace
	case r == '_':
		return timeNodeDigitOrSpace
	case r == '+' || r == '-' || r == 'z' || r == 'Z':
		return timeNodePlusOrMinus
	}

	return timeNodeLiteral
}

func timeStep(r rune, cur *timeNode) *timeNode {
	t := tnType(r)

	for _, n := range cur.children {
		if (n.ntype == timeNodeDigitOrSpace && (t == timeNodeDigit || t == timeNodeSpace)) ||
			(n.ntype == t && (t != timeNodeLiteral || (t == timeNodeLiteral && n.value == r))) {

			return n
		}
	}

	return nil
}
