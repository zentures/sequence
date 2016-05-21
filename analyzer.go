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
	"unicode"

	"github.com/willf/bitset"
	"github.com/zhenjl/porter2"
	"github.com/zhenjl/xparse/etld"
)

// Analyzer builds an analysis tree that represents all the Sequences from messages.
// It can be used to determine all of the unique patterns for a large body of messages.
//
// It's based on a single basic concept, that for multiple log messages, if tokens in
// the same position shares one same parent and one same child, then the tokens in
// that position is likely variable string, which means it's something we can extract.
// For example, take a look at the following two messages:
//
//   Jan 12 06:49:42 irc sshd[7034]: Accepted password for root from 218.161.81.238 port 4228 ssh2
//   Jan 12 14:44:48 jlz sshd[11084]: Accepted publickey for jlz from 76.21.0.16 port 36609 ssh2
//
// The first token of each message is a timestamp, and the 3rd token of each message
// is the literal "sshd". For the literals "irc" and "jlz", they both share a common
// parent, which is a timestamp. They also both share a common child, which is "sshd".
// This means token in between these, the 2nd token in each message, likely represents
// a variable token in this message type. In this case, "irc" and "jlz" happens to
// represent the syslog host.
//
// Looking further down the message, the literals "password" and "publickey" also
// share a common parent, "Accepted", and a common child, "for". So that means the
// token in this position is also a variable token (of type TokenString).
//
// You can find several tokens that share common parent and child in these two
// messages, which means each of these tokens can be extracted. And finally, we can
// determine that the single pattern that will match both is:
//
//   %time% %string% sshd [ %integer% ] : Accepted %string% for %string% from %ipv4% port %integer% ssh2
//
// If later we add another message to this mix:
//
//   Jan 12 06:49:42 irc sshd[7034]: Failed password for root from 218.161.81.238 port 4228 ssh2
//
// The Analyzer will determine that the literals "Accepted" in the 1st message, and
// "Failed" in the 3rd message share a common parent ":" and a common child "password",
// so it will determine that the token in this position is also a variable token.
// After all three messages are analyzed, the final pattern that will match all three
// messages is:
//
//   %time% %string% sshd [ %integer% ] : %string% %string% for %string% from %ipv4% port %integer% ssh2
type Analyzer struct {
	root *analyzerNode
	leaf *analyzerNode

	levels    [][]*analyzerNode
	litmaps   []map[string]int
	nodeCount []int

	mu sync.RWMutex
}

type analyzerNode struct {
	Token

	index int
	level int

	isKey   bool
	isValue bool

	leaf bool

	parents  *bitset.BitSet
	children *bitset.BitSet
}

type stackAnalyzerNode struct {
	node  *analyzerNode
	level int
	score int
}

func (this *stackAnalyzerNode) String() string {
	return fmt.Sprintf("level=%d, score=%d, token=%v, leaf=%t", this.level, this.score, this.node.Token, this.node.leaf)
}

func NewAnalyzer() *Analyzer {
	tree := &Analyzer{
		root: newAnalyzerNode(),
		leaf: newAnalyzerNode(),
	}

	tree.root.level = -1

	return tree
}

func newAnalyzerNode() *analyzerNode {
	return &analyzerNode{
		parents:  bitset.New(1),
		children: bitset.New(1),
	}
}

func (this *analyzerNode) String() string {
	return fmt.Sprintf("%d/%d: %s %t %t %t\n--%s\n--%s\n", this.level, this.index, this.Token.String(),
		this.isKey, this.isValue, this.leaf, this.parents.DumpAsBits(), this.children.DumpAsBits())
}

// Analyze analyzes the message sequence supplied, and returns the unique pattern
// that will match this message.
func (this *Analyzer) Analyze(seq Sequence) (Sequence, error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	path, err := this.analyzeMessage(seq)
	if err != nil {
		return nil, err
	}

	var seq2 Sequence

	for i, n := range path {
		n.Token.Value, n.Token.isKey, n.Token.isValue = seq[i].Value, seq[i].isKey, seq[i].isValue
		seq2 = append(seq2, n.Token)
	}

	//glog.Debugf("%s", seq2.PrintTokens())

	return analyzeSequence(seq2), nil
}

// Add adds a single message sequence to the analysis tree. It will not determine
// if the tokens share a common parent or child at this point. After all the
// sequences are added, then Finalize() should be called.
func (this *Analyzer) Add(seq Sequence) error {
	this.mu.Lock()
	defer this.mu.Unlock()

	seq = markSequenceKV(seq)

	// Add enough levels to support the depth of the token list
	if l := len(seq) - len(this.levels) + 1; l > 0 {
		newlevels := make([][]*analyzerNode, l)
		// the maps are used to hash literals to see if they exist
		newmaps := make([]map[string]int, l)

		for i := 0; i < l; i++ {
			newlevels[i] = make([]*analyzerNode, allTypesCount)
			newlevels[i][0] = this.leaf
			newmaps[i] = make(map[string]int)
		}

		this.levels = append(this.levels, newlevels...)
		this.litmaps = append(this.litmaps, newmaps...)
	}

	parent := this.root

	for i, token := range seq {
		vl := len(token.Value)
		//more, rest := false, false

		if vl >= 2 && token.Value[0] == '%' && token.Value[vl-1] == '%' {
			if f := name2TagType(token.Value); f != TagUnknown {
				token.Tag = f
				token.Type = f.TokenType()
			} else if t := name2TokenType(token.Value); t != TokenUnknown {
				token.Type = t
				token.Tag = TagUnknown
			}
		}

		var foundNode *analyzerNode

		switch {
		case token.Tag != TagUnknown:
			// if Tag is not TagUnknown, it means the Tag is one of the recognized
			// tag type. In this case, we just add it to the list of tag types.

			if foundNode = this.levels[i][int(token.Tag)]; foundNode == nil {
				foundNode = newAnalyzerNode()
				foundNode.Token = token
				foundNode.level = i
				foundNode.index = int(token.Tag)
				this.levels[i][foundNode.index] = foundNode
			}

		case token.Type != TokenUnknown && token.Type != TokenLiteral:
			// If this is a known token type but it's not a literal, it means this
			// token could contain different values. In this case, we add it to the
			// list of token types.

			if foundNode = this.levels[i][TagTypesCount+int(token.Type)]; foundNode == nil {
				foundNode = newAnalyzerNode()
				foundNode.Token = token
				foundNode.level = i
				foundNode.index = TagTypesCount + int(token.Type)
				this.levels[i][foundNode.index] = foundNode
			}

		case token.Tag == TagUnknown && token.Type == TokenLiteral:
			// if the tag type is unknown, and the token type is literal, that
			// means this is some type of string we parsed from the message.

			// If we have gotten here, it means we found a string that we cannot
			// determine if it's a fixed literal, or a changing variable. So we have
			// to keep this in the literal map to track it.
			// If we have seen this literal before, then there's already a node
			if j, ok := this.litmaps[i][token.Value]; ok {
				foundNode = this.levels[i][j]
			} else {
				// Otherwise we create a new node for this first time literal,
				// add it to the end of the nodes for this level, and keep track
				// of the index in the slice/list in the literal map so we can
				// quick it find its location later.
				foundNode = newAnalyzerNode()
				this.levels[i] = append(this.levels[i], foundNode)
				foundNode.Token = token
				foundNode.level = i
				foundNode.index = len(this.levels[i]) - 1
				foundNode.Tag = TagUnknown
				this.litmaps[i][foundNode.Value] = foundNode.index
				foundNode.isKey = token.isKey
			}
		}

		// We use a bitset to track parent and child relationships. In this case,
		// we set the parent bit for the index of the current node, and set the
		// child bit for the index of the parent node.
		if parent != nil {
			foundNode.parents.Set(uint(parent.index))
			parent.children.Set(uint(foundNode.index))
		}

		parent = foundNode
	}

	// If we are finished with all the tokens, then the current parent node is the
	// last node we created, which means it's a leaf node.
	parent.leaf = true

	// We set the 0th bit of the children bitset ...
	parent.children.Set(0)

	return nil
}

// Finalize will go through the analysis tree and determine which tokens share common
// parent and child, merge all the nodes that share at least 1 parent and 1 child,
// and finally compact the tree and remove all dead nodes.
func (this *Analyzer) Finalize() error {
	this.mu.Lock()
	defer this.mu.Unlock()

	//fmt.Printf("in finalize\n")
	if err := this.merge(); err != nil {
		return err
	}

	return this.compact()
}

// merge merges trie[i][k] into trie[i][j] and updates all parents and children
// appropriately
func (this *Analyzer) merge() error {
	// For every level of this tree ...
	for i, level := range this.levels {
		// And for every literal child of this level ...
		// remember literal children starts after all the types, thus j := allTypesCount
		for j := allTypesCount; j < len(level); j++ {
			cur := level[j]

			// - If the node is nil, then most likely it's been merged, so let's move on.
			// - If the node is a key (isKey == true), then it's a literal that shouldn't
			//   be merged, so let's move on.
			// - If the node is a single character literal, and it's not a character in
			//   a-zA-Z, then it shouldn't be merged, so let's move on.
			if cur == nil || cur.isKey ||
				(cur.Type == TokenLiteral && len(cur.Value) == 1 &&
					!((cur.Value[0] >= 'a' && cur.Value[0] <= 'z') || (cur.Value[0] >= 'A' && cur.Value[0] <= 'Z'))) {
				continue
			}

			// Finds the nodes that share at least 1 parent and 1 child with trie[i][j]
			// These will be the nodes that get merged into j
			mergeSet, err := this.getMergeSet(i, j, cur)
			if err != nil {
				return err
			}

			// if the number of nodes share at least 1 parent and 1 child is only 1, then
			// it means it's only the curernt node left. In other words, no other nodes share
			// at least 1 parent and 1 child with the current node. If so, move on.
			if mergeSet.Count() > 1 {
				// Otherwise, we want to merge the nodes that are in the mergeSet

				// parents is the new parent bitset after the merging of all relevant nodes
				parents := cur.parents

				// children is the new children bitset after merging all relevant nodes
				children := cur.children

				leaf := cur.leaf

				// For every node aside from the current node, let's merge their info
				// into the current node (cur)
				//
				// Check to see if the kth bit is set, if so, then we merge the kth node
				// into current node

				for k, e := mergeSet.NextSet(uint(j) + 1); e; k, e = mergeSet.NextSet(uint(k) + 1) {

					// The parents of the final merged node is the combination of all
					// parents from all the merge nodes
					parents.InPlaceUnion(level[k].parents)

					// The children of the final merged node is the combination of all
					// children from all the merge nodes
					children.InPlaceUnion(level[k].children)

					if leaf || level[k].leaf {
						leaf = true
					}

					// Once we merge the parent and children bitset, we need to make sure
					// all the parents of the merged node no longer points to the merged
					// node, so we go through each parent and clear the kth child bit
					//
					// Make sure we are not at the top level since there's no more levels
					// above it
					if i > 0 {
						plen := int(level[k].parents.Len())

						for l := 0; l < plen; l++ {
							// For each of the set parent bit of the kth node, we clear
							// the kth child bit in the parent's children bitset
							//
							// Also, we set the parent's jth child bit since the parent
							// needs to point to the new merged node
							if level[k].parents.Test(uint(l)) {
								this.levels[i-1][l].children.Clear(uint(k))
								this.levels[i-1][l].children.Set(uint(j))
							}
						}
					}

					// Same for all the children of the merged node. For each of the
					// children, we clear the kth parent bit
					//
					// Make sure we are not at the bottom level since there's no more
					// levels below
					if i < len(this.levels)-1 {
						for l := 0; l < int(level[k].children.Len()); l++ {
							// For each of the set child bit of the kth node, we clear
							// the kth parent bit in the child's parents bitset
							//
							// Also, we set the child's jth parent bit since the parent
							// needs to point to the new merged node
							if level[k].children.Test(uint(l)) {
								this.levels[i+1][l].parents.Clear(uint(k))
								this.levels[i+1][l].parents.Set(uint(j))
							}
						}
					}

					level[k] = nil
				}

				cur.parents = parents
				cur.children = children
				cur.leaf = leaf
				cur.Type = TokenString
			}
		}
	}

	return nil
}

// getMergeSet finds the nodes that share at least 1 parent and 1 child with trie[i][j]
// These will be the nodes that get merged into j
func (this *Analyzer) getMergeSet(i, j int, cur *analyzerNode) (*bitset.BitSet, error) {
	level := this.levels[i]

	// shareParents is a bitset marks all the nodes that share at least 1 parent
	// with the current node being checked
	shareParents := bitset.New(uint(len(level)))

	// shareChildren is a bitset marks all the nodes that share at least 1 child
	// with the current node being checked
	shareChildren := bitset.New(uint(len(level)))

	// Set the current node's bit in both shareParents and shareChildren
	shareParents.Set(uint(j))
	shareChildren.Set(uint(j))

	// For each node after the current constant/word node, check to see if there's
	// any that share at least 1 parent or 1 child
	for k, tmp := range level[j+1:] {
		// - If node if nil, then most likely have been merged, let's move on
		// - We only merge nodes that are literals or strings, anything else
		//   is already a variable so move on
		// - If node is a single character literal, then not merging, move on
		if tmp == nil ||
			(tmp.Type != TokenLiteral && tmp.Type != TokenString) ||
			(tmp.Type == TokenLiteral && len(tmp.Value) == 1) {

			continue
		}

		// Take the intersection of current node's parent bitset and the next
		// constant/word node's parent bitset, if the cardinality of the result
		// bitset is greater than 0, then it means they share at least 1 parent.
		// If so, then set the bit that represent that node in shareParent.
		if c := cur.parents.IntersectionCardinality(tmp.parents); c > 0 {
			shareParents.Set(uint(k + j + 1))
		}

		// Take the intersection of current node's children bitset and the next
		// constant/word node's children bitset, if the cardinality of the result
		// bitset is greater than 0, then it means they share at least 1 child.
		// If so, then set the bit that represent that node in shareChildren.
		if c := cur.children.IntersectionCardinality(tmp.children); c > 0 {
			shareChildren.Set(uint(k + j + 1))
		}
	}

	// The goal is to identify all nodes that share at least 1 parent and 1 child
	// with the current node. Now that we have all the nodes that share at least
	// 1 parent in shareParents, and all the nodes that share at least 1 child
	// in shareChildren, we can then take the intersection of shareParent and
	// shareChildren to get all the nodes that share both
	mergeSet := shareParents.Intersection(shareChildren)

	return mergeSet, nil
}

func (this *Analyzer) compact() error {
	// Build a complete new trie
	newLevels := make([][]*analyzerNode, len(this.levels))

	// Each level has a hash map of literals that points to the literal's
	// index position in the level slice
	newmaps := make([]map[string]int, len(this.litmaps))
	for i := 0; i < len(newmaps); i++ {
		newmaps[i] = make(map[string]int)
	}

	this.nodeCount = make([]int, len(this.levels))

	// Copy all the fixed children (leaf, TokenNames, TagTokenMap) into the slice
	// Copy any non-nil children into the slice
	// Fix the index for all the children
	// Add any literals to the hash
	for i, level := range this.levels {
		for j, cur := range level {
			if j < allTypesCount || cur != nil {
				newLevels[i] = append(newLevels[i], cur)

				if cur != nil {
					this.nodeCount[i]++
					cur.index = len(newLevels[i]) - 1

					if cur.Type == TokenLiteral {
						newmaps[i][cur.Value] = cur.index
					}
				}
			}
		}

	}

	// Reset all the parents and children relationship for each node
	for i, level := range newLevels {
		for _, cur := range level {
			if cur == nil {
				continue
			}

			newParents := bitset.New(1)

			if i > 0 {
				for k, e := cur.parents.NextSet(0); e; k, e = cur.parents.NextSet(k + 1) {
					// recall that index is already set to the index of the newLevels
					newParents.Set(uint(this.levels[i-1][k].index))
				}
			} else {
				newParents.Set(0)
			}

			newChildren := bitset.New(1)

			if i < len(newLevels)-1 {
				for k, e := cur.children.NextSet(0); e; k, e = cur.children.NextSet(k + 1) {
					newChildren.Set(uint(this.levels[i+1][k].index))
				}
			}

			cur.parents = newParents
			cur.children = newChildren

			if cur.Type != TokenLiteral {
				cur.Value = ""
			}
		}
	}

	this.levels = newLevels
	this.litmaps = newmaps

	return nil
}

func (this *Analyzer) analyzeMessage(seq Sequence) ([]*analyzerNode, error) {
	var (
		cur stackAnalyzerNode

		// Keep track of the path we have walked
		// +1 because the first level is the root node, so the actual path is going
		// to be level 1 .. n. When we return the actual path we will get rid of the
		// first element in the slice.
		path []*analyzerNode = make([]*analyzerNode, len(seq)+1)

		// Keeps track of ALL paths of the matched patterns
		paths [][]*analyzerNode

		bestScore int
		bestPath  int
	)

	// toVisit is a stack, nodes that need to be visited are appended to the end,
	// and we take nodes from the end to visit
	toVisit := append(make([]stackAnalyzerNode, 0, 100), stackAnalyzerNode{this.root, 0, 0})

	// Depth-first analysis of the message using the current tree
	for len(toVisit) > 0 {
		// Take the last node from the stack to visit
		cur = toVisit[len(toVisit)-1]

		//glog.Debugf("cur=%s, len(path)=%d", cur.String(), len(path))

		// Delete the last node from the stack
		toVisit = toVisit[:len(toVisit)-1]

		if cur.level <= len(path) {
			// If we are here, then the current level is less than the number of tokens,
			// then we can assume this is still a possible path. So let's track it.
			path[cur.level] = cur.node
		}

		// If the current level we are visiting is greater or equal to the number of
		// tokens in the message, that means we have exhausted the message length. If
		// the current node is also a leaf node, it means we have matched a pattern,
		// so let's calculate the scores and max depth of this path, save the depth,
		// score and path, and then move on to the next possible path.
		if cur.level >= len(seq) {
			// If this is a leaf node, that means we are at the end of the tree, and
			// since this is also the last token, it means we have a match. If it's
			// not a leaf node, it means we do not have a match.
			if cur.node.leaf {
				tmppath := append(make([]*analyzerNode, 0, len(path)-1), path[1:]...)
				paths = append(paths, tmppath)

				if cur.score > bestScore {
					bestScore = cur.score
					bestPath = len(paths) - 1
				}
			}

			continue
		}

		token := seq[cur.level]

		// For each of the child for the current node, we test to see if they should
		// be added to the stack for visiting.
		for i, e := cur.node.children.NextSet(0); e; i, e = cur.node.children.NextSet(i + 1) {
			node := this.levels[cur.node.level+1][i]

			if node != nil {
				// Anything other than these 3 conditions are considered no match.
				switch {
				case node.Type == token.Type && token.Type != TokenLiteral && token.Type != TokenString:
					// If the child node and the msg token have the same type, and
					// type is not a literal or a string, that means we have a match
					// for this level, so let's add it to the stack to visit.
					//
					// This is also considered a full match since the types matched
					toVisit = append(toVisit, stackAnalyzerNode{node, cur.level + 1, cur.score + fullMatchWeight})

				case node.Type == TokenString && token.Type == TokenLiteral &&
					(len(token.Value) != 1 || (len(token.Value) == 1 && this.isValidCharacter(rune(token.Value[0])))):
					// If the node is a string and token is a non-one-character literal,
					// then it's considered a partial match, since a literal is
					// technically a string.
					toVisit = append(toVisit, stackAnalyzerNode{node, cur.level + 1, cur.score + partialMatchWeight})

				case node.Type == TokenLiteral && token.Type == TokenLiteral && node.Value == token.Value:
					// If the parse node and token are both literal type, then the
					// value must also match. If matched, then let's add to the stack
					// for visiting.
					//
					// Because the literal value matched, this is also considered to
					// be a full match.
					toVisit = append(toVisit, stackAnalyzerNode{node, cur.level + 1, cur.score + fullMatchWeight})

				case token.Type == TokenString && token.isValue:
					toVisit = append(toVisit, stackAnalyzerNode{node, cur.level + 1, cur.score + fullMatchWeight})
				}
			}
		}
	}

	if len(paths) > bestPath {
		//return paths[bestPath], maxs[bestPath], nil
		return paths[bestPath], nil
	}

	return nil, ErrNoMatch
}

func (this *Analyzer) isValidCharacter(value rune) bool {
	return (unicode.IsLetter(value) || value == rune('|'))
}

func (this *Analyzer) dump() int {
	total := 0
	for i, l := range this.levels {
		fmt.Printf("level %d (%d children):\n", i, len(l))
		total += len(l)

		for j, n := range l {
			if n != nil {
				fmt.Printf("node %d.%d: %s %s - %s\n", i, j, n.Type, n.Tag, n)
			}
		}
	}

	return total
}

func (this *Analyzer) dumpTree() {
	for i, l := range this.levels {
		space := ""
		for k := 0; k < i; k++ {
			space += "  "
		}

		for j, n := range l {
			if n != nil && j != 0 {
				fmt.Printf("%s %d/%d: %s\n", space, i, j, n.Token)
			}
		}
	}
}

func markSequenceKV(seq Sequence) Sequence {
	// Step 1: mark all key=value pairs
	l := len(seq)
	for i := l - 1; i >= 0; i-- {
		if seq[i].Value == "=" {
			ki := i - 1 // key index
			vi := i + 1 // value index

			if vi < l && seq[vi].Type == TokenLiteral &&
				(seq[vi].Value == "\"" || seq[vi].Value == "'" || seq[vi].Value == "<") {
				vi = i + 2
			}

			// if the value index is smaller than the last node index, that means
			// there's a node after the "=". If the node at value index is NOT
			// already a key, then it's likely a value. Let's mark it.
			if vi < l && !seq[vi].isKey &&
				!(seq[vi].Value == "\"" || seq[vi].Value == "'" || seq[vi].Value == "<") {

				seq[vi].isValue = true

				if seq[vi].Type == TokenLiteral {
					seq[vi].Type = TokenString
				}
			}

			// if the key index is greater or equal to 0, which means there's
			// a token before the "=", if it's a literal, then it's very likely
			// a key, so let's mark that
			if ki >= 0 && seq[ki].Type == TokenLiteral {
				seq[ki].isKey = true
			}
		}
	}

	return seq
}

func analyzeSequence(seq Sequence) Sequence {
	l := len(seq)
	var fexists = make([]bool, TagTypesCount)

	defer func() {
		// Step 7: try to see if we can find any srcport and dstport tags
		for i, tok := range seq {
			if tok.Type == token__host__ || tok.Type == token__email__ {
				seq[i].Type = TokenString
			}

			if i < l-2 && tok.Type == TokenIPv4 && (seq[i+1].Value == "/" || seq[i+1].Value == ":") &&
				seq[i+2].Type == TokenInteger {

				switch tok.Tag {
				case TagSrcIP:
					seq[i+2].Tag = TagSrcPort
					seq[i+2].Type = seq[i+2].Tag.TokenType()
					fexists[seq[i+2].Tag] = true

				case TagDstIP:
					seq[i+2].Tag = TagDstPort
					seq[i+2].Type = seq[i+2].Tag.TokenType()
					fexists[seq[i+2].Tag] = true

				case TagSrcIPNAT:
					seq[i+2].Tag = TagSrcPortNAT
					seq[i+2].Type = seq[i+2].Tag.TokenType()
					fexists[seq[i+2].Tag] = true

				case TagDstIPNAT:
					seq[i+2].Tag = TagDstPortNAT
					seq[i+2].Type = seq[i+2].Tag.TokenType()
					fexists[seq[i+2].Tag] = true
				}

			}
		}

		//glog.Debugf("7. %s", seq)

	}()

	// Step 1: mark all key=value pairs, as well as any prekey words as key
	seq = markSequenceKV(seq)

	for i, tok := range seq {
		if _, ok := keymaps.prekeys[tok.Value]; ok {
			seq[i].isKey = true
		}
	}

	// Step 2: lower case all literals, and try to recognize emails and host names
	for i, tok := range seq {
		if tok.Type == TokenLiteral && tok.Tag == TagUnknown {
			seq[i].Value = strings.ToLower(tok.Value)

			// Matching a effective top level domain
			if etld.Match(tok.Value) > 0 {
				// Matching an email address
				if strings.Index(tok.Value, "@") > 0 {
					seq[i].Type = token__email__
				} else if strings.Index(tok.Value, ".") > 0 {
					seq[i].Type = token__host__
				}
			}
		}
	}

	//glog.Debugf("2. %s", seq.PrintTokens())

	// Step 3: try to recognize syslog headers (RFC5424 and RFC3164)
	// RFC5424
	// - "1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 ..."
	// - "1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - ..."
	// - "1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 ..."
	// RFC3164
	// - "Oct 11 22:14:15 mymachine su: ..."
	// - "Aug 24 05:34:00 CST 1987 mymachine myproc[10]: ..."
	if len(seq) >= 6 && seq[0].Type == TokenInteger && seq[1].Type == TokenTime &&
		(seq[2].Type == TokenIPv4 || seq[2].Type == TokenIPv6 || seq[2].Type == token__host__ || seq[2].Type == TokenLiteral || seq[2].Type == TokenString) &&
		seq[3].Type == TokenLiteral &&
		(seq[4].Type == TokenInteger || (seq[4].Type == TokenLiteral && seq[4].Value == "-")) &&
		(seq[5].Type == TokenLiteral) {

		// RFC5424 header format
		// message time
		seq[1].Tag = TagMsgTime
		seq[1].Type = seq[1].Tag.TokenType()
		fexists[seq[1].Tag] = true

		// app ip or hostname
		switch seq[2].Type {
		case TokenIPv4:
			seq[2].Tag = TagAppIP

		case token__host__, TokenLiteral, TokenString:
			seq[2].Tag = TagAppHost
		}

		seq[2].Type = seq[2].Tag.TokenType()
		fexists[seq[2].Tag] = true

		// appname
		seq[3].Tag = TagAppName
		seq[3].Type = seq[3].Tag.TokenType()
		fexists[seq[3].Tag] = true

		// session id (or proc id)
		seq[4].Tag = TagSessionID
		seq[4].Type = seq[4].Tag.TokenType()
		fexists[seq[4].Tag] = true

		// message id
		seq[5].Tag = TagMsgId
		seq[5].Type = seq[5].Tag.TokenType()
		fexists[seq[5].Tag] = true
	} else if len(seq) >= 4 && seq[0].Type == TokenTime &&
		(seq[1].Type == TokenIPv4 || seq[1].Type == TokenIPv6 || seq[1].Type == token__host__ || seq[1].Type == TokenLiteral || seq[1].Type == TokenString) &&
		(seq[2].Type == TokenLiteral || seq[2].Type == TokenString) &&
		(seq[3].Type == TokenLiteral && seq[3].Value == ":") {

		// RFC3164 format 1 - "Oct 11 22:14:15 mymachine su: ..."
		// message time
		seq[0].Tag = TagMsgTime
		seq[0].Type = seq[0].Tag.TokenType()
		fexists[seq[0].Tag] = true

		// app ip or hostname
		switch seq[1].Type {
		case TokenIPv4:
			seq[1].Tag = TagAppIP

		case token__host__, TokenLiteral, TokenString:
			seq[1].Tag = TagAppHost
		}

		seq[1].Type = seq[1].Tag.TokenType()
		fexists[seq[1].Tag] = true

		// appname
		seq[2].Tag = TagAppName
		seq[2].Type = seq[2].Tag.TokenType()
		fexists[seq[2].Tag] = true
	} else if len(seq) >= 7 && seq[0].Type == TokenTime &&
		(seq[1].Type == TokenIPv4 || seq[1].Type == TokenIPv6 || seq[1].Type == token__host__ || seq[1].Type == TokenLiteral || seq[1].Type == TokenString) &&
		(seq[2].Type == TokenLiteral || seq[2].Type == TokenString) &&
		(seq[3].Type == TokenLiteral && seq[3].Value == "[") &&
		(seq[4].Type == TokenInteger) &&
		(seq[5].Type == TokenLiteral && seq[5].Value == "]") &&
		(seq[6].Type == TokenLiteral && seq[6].Value == ":") {

		// RFC3164 format 2 - "Aug 24 05:34:00 CST 1987 mymachine myproc[10]: ..."
		// message time
		seq[0].Tag = TagMsgTime
		seq[0].Type = seq[0].Tag.TokenType()
		fexists[seq[0].Tag] = true

		// app ip or hostname
		switch seq[1].Type {
		case TokenIPv4:
			seq[1].Tag = TagAppIP

		case token__host__, TokenLiteral, TokenString:
			seq[1].Tag = TagAppHost
		}

		seq[1].Type = seq[1].Tag.TokenType()
		fexists[seq[1].Tag] = true

		// appname
		seq[2].Tag = TagAppName
		seq[2].Type = seq[2].Tag.TokenType()
		fexists[seq[2].Tag] = true

		// session id (or proc id)
		seq[4].Tag = TagSessionID
		seq[4].Type = seq[4].Tag.TokenType()
		fexists[seq[4].Tag] = true
	} else if len(seq) >= 7 && seq[0].Type == TokenTime &&
		(seq[1].Type == TokenIPv4 || seq[1].Type == TokenIPv6 || seq[1].Type == token__host__ || seq[1].Type == TokenLiteral || seq[1].Type == TokenString) &&
		seq[2].Value == "last" {

		// "jan 12 06:49:56 irc last message repeated 6 times"
		// message time
		seq[0].Tag = TagMsgTime
		seq[0].Type = seq[0].Tag.TokenType()
		fexists[seq[0].Tag] = true

		// app ip or hostname
		switch seq[1].Type {
		case TokenIPv4:
			seq[1].Tag = TagAppIP

		case token__host__, TokenLiteral, TokenString:
			seq[1].Tag = TagAppHost
		}

		seq[1].Type = seq[1].Tag.TokenType()
		fexists[seq[1].Tag] = true
	}

	// glog.Debugf("3. %s", seq)

	// Step 5: identify the likely tags by their prekeys (literals that usually
	// exist before non-literals). All values must be within 2 tokens away, not
	// counting single character non-a-zA-Z tokens.
	distance := 2

LOOP:
	for i, tok := range seq {
		// Only mark unknown tokens
		if tok.Tag != TagUnknown {
			continue
		}

		//glog.Debugf("1. checking tok=%q", tok)

		if tags, ok := keymaps.prekeys[tok.Value]; ok {

			// This token is a matching prekey

			// Match anyting non-string tags first
			for _, f := range tags {

				if fexists[f] || f.TokenType() == TokenString || f.TokenType() == TokenUnknown {
					continue
				}

				var j int // j is the number of tokens away from the key

				// This is a specific type, so match the type, within the next 2 tokens
				// away, not counting single character non-a-zA-Z tokens.
				for k := i + 1; k < l && j < distance; k++ {
					if !fexists[f] && seq[k].Tag == TagUnknown && f.TokenType() == seq[k].Type && !seq[k].isKey {
						seq[k].Tag = f
						seq[k].Type = seq[k].Tag.TokenType()
						fexists[seq[k].Tag] = true

						//glog.Debugf("found something for tok=%q", tok)

						// Found what we need, let's go to the next token
						continue LOOP
					}

					if seq[k].Type != TokenLiteral ||
						(seq[k].Type == TokenLiteral && len(seq[k].Value) > 1) ||
						(seq[k].Type == TokenLiteral && len(seq[k].Value) == 1 &&
							((seq[k].Value[0] >= 'a' && seq[k].Value[0] <= 'z') ||
								(seq[k].Value[0] >= 'A' && seq[k].Value[0] <= 'Z'))) {

						j++
					}
				}
			}

			for _, f := range tags {

				//glog.Debugf("2. checking tok=%q", tok)

				// If the tag type is already taken, move on
				// Should ONLY have TokenString left not touched
				if fexists[f] || f.TokenType() != TokenString {
					continue
				}

				switch f {
				case TagSrcHost, TagDstHost, TagSrcEmail, TagDstEmail:
					for k := i + 1; k < l && k < i+distance; k++ {
						if !fexists[f] && seq[k].Tag == TagUnknown && !seq[k].isKey &&
							(seq[k].Type == token__host__ && (f == TagSrcHost || f == TagDstHost)) ||
							(seq[k].Type == token__email__ && (f == TagSrcEmail || f == TagDstEmail)) {

							seq[k].Tag = f
							seq[k].Type = seq[k].Tag.TokenType()
							fexists[seq[k].Tag] = true
							continue LOOP
						}
					}

				default:
					var j int // j is the number of tokens away from the key

					// This is a regular string type, let's find a literal or string
					// token, within the next 2 tokens
					for k := i + 1; k < l && j < distance; k++ {
						// if the value tag type is a string, then we only look for
						// either TokenString or TokenLiteral tokens in the next one or
						// two tokens. The token should not include any single character
						// literals that are not a-zA-Z.
						if seq[k].Tag == TagUnknown && !seq[k].isKey &&
							(seq[k].Type == TokenString ||
								(seq[k].Type == TokenLiteral && len(seq[k].Value) > 1) ||
								(seq[k].Type == TokenLiteral && len(seq[k].Value) == 1 &&
									((seq[k].Value[0] >= 'a' && seq[k].Value[0] <= 'z') ||
										(seq[k].Value[0] >= 'A' && seq[k].Value[0] <= 'Z')))) {

							seq[k].Tag = f
							seq[k].Type = seq[k].Tag.TokenType()
							fexists[seq[k].Tag] = true
							continue LOOP
						}

						if seq[k].Type != TokenLiteral ||
							(seq[k].Type == TokenLiteral && len(seq[k].Value) > 1) ||
							(seq[k].Type == TokenLiteral && len(seq[k].Value) == 1 &&
								((seq[k].Value[0] >= 'a' && seq[k].Value[0] <= 'z') ||
									(seq[k].Value[0] >= 'A' && seq[k].Value[0] <= 'Z'))) {

							j++
						}
					}
				}
			}
		}
	}

	//glog.Debugf("5. %s", seq)

	// Step 4: match any key actions, statuses, objects and other keywords, and mark
	// accordingly We do seq step after the k=v step so we don't mistakenly mark
	// any keys
	for i, tok := range seq {
		if !tok.isKey && !tok.isValue && (tok.Type == TokenLiteral || tok.Type == TokenString) && tok.Tag == TagUnknown {
			pw := porter2.Stem(tok.Value)
			if f, ok := keymaps.keywords[pw]; ok {
				if !fexists[f] {
					seq[i].Tag = f
					seq[i].Type = f.TokenType()
					fexists[f] = true
				}
			}
		}
	}

	//glog.Debugf("4. %s", seq)
	// Step 6: look for the first and second of these types, and mark accordingly
	for i, tok := range seq {
		if tok.Tag == TagUnknown {
			switch tok.Type {
			case TokenTime:
				if !fexists[TagMsgTime] {
					seq[i].Tag = TagMsgTime
					seq[i].Type = seq[i].Tag.TokenType()
					fexists[TagMsgTime] = true
				}

			case TokenURI:
				if !fexists[TagObject] {
					seq[i].Tag = TagObject
					seq[i].Type = seq[i].Tag.TokenType()
					fexists[TagObject] = true
				}

			case TokenMac:
				if !fexists[TagSrcMac] {
					seq[i].Tag = TagSrcMac
					seq[i].Type = seq[i].Tag.TokenType()
					fexists[TagSrcMac] = true
				} else if !fexists[TagDstMac] {
					seq[i].Tag = TagDstMac
					seq[i].Type = seq[i].Tag.TokenType()
					fexists[TagDstMac] = true
				}

			case TokenIPv4:
				if !fexists[TagSrcIP] {
					seq[i].Tag = TagSrcIP
					seq[i].Type = seq[i].Tag.TokenType()
					fexists[TagSrcIP] = true
				} else if !fexists[TagDstIP] {
					seq[i].Tag = TagDstIP
					seq[i].Type = seq[i].Tag.TokenType()
					fexists[TagDstIP] = true
				}

			case token__host__:
				if !fexists[TagSrcHost] {
					seq[i].Tag = TagSrcHost
					seq[i].Type = seq[i].Tag.TokenType()
					fexists[TagSrcHost] = true
				} else if !fexists[TagDstHost] {
					seq[i].Tag = TagDstHost
					seq[i].Type = seq[i].Tag.TokenType()
					fexists[TagDstHost] = true
				}

			case token__email__:
				if !fexists[TagSrcEmail] {
					seq[i].Tag = TagSrcEmail
					seq[i].Type = seq[i].Tag.TokenType()
					fexists[TagSrcEmail] = true
				} else if !fexists[TagDstEmail] {
					seq[i].Tag = TagDstEmail
					seq[i].Type = seq[i].Tag.TokenType()
					fexists[TagDstEmail] = true
				}
			}
		}
	}

	//glog.Debugf("6. %s", seq)

	return seq
}
