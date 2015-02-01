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

// Package sequence is a library for a _sequential semantic log parser_.
//
// It is _sequential_ because it goes through a log message sequentially and does not
// use regular expressions. It is _semantic_ because it tries to extract meaningful
// information out of the log messages and give them semantic indicators, e.g.,
// src IPv4 or dst IPv4. It is an _analyzer_ because analyzes a large corpus of
// text-based log messages and try to determine the unique patterns that would
// represent all of them. It is a _parser_ because it will take a message and
// parses out the meaningful parts.
//
// ### Motivation
//
// Log messages are notoriusly difficult to parse because they all have different
// formats. Industries (see Splunk, ArcSight, Tibco LogLogic, Sumo Logic, Logentries,
// Loggly, LogRhythm, etc etc etc) have been built to solve the problems of parsing,
// understanding and analyzing log messages.
//
// Let's say you have a bunch of log files you like to parse. The first problem you
// will typically run into is you have no way of telling how many DIFFERENT types of
// messages there are, so you have no idea how much work there will be to develop
// rules to parse all the messages. Not only that, you have hundreds of thousands,
// if not  millions of messages, in front of you, and you have no idea what messages
// are worth parsing, and what's not.
//
// The typical workflow is develop a set of regular expressions and keeps testing
// against the logs until some magical moment where all the logs you want parsed are
// parsed. Ask anyone who does this for a living and they will tell you this process
// is long, frustrating and error-prone.
//
// Even after you have developed a set of regular expressions that match the original
// set of messages, if new messages come in, you will have to determine which of
// the new messages need to be parsed. And if you develop a new set of regular
// expressions to parse those new messages, you still have no idea if the regular
// expressions will conflict with the ones you wrote before. If you write your regex
// parsers too liberally, it can easily parse the wrong messages.
//
// After all that, you will end up finding out the regex parsers are quite slow.
// It can typically parse several thousands messages per second. Given enough CPU
// resources on a large enough machine, regex parsers can probably parse tens of
// thousands of messages per second. Even to achieve this type of performance, you
// will likely need to limit the number of regular expressions the parser has. The
// more regex rules, the slower the parser will go.
//
// To work around this performance issue, companies have tried to separate the
// regex rules for different log message types into different parsers. For example,
// they will have a parser for Cisco ASA logs, a parser for sshd logs, a parser
// for Apache logs, etc etc. And then they will require the users to tell them
// which parser to use (usually by indicating the log source type of the originating
// IP address or host.)
//
// Sequence is developed to make analyzing and parsing log messages a lot easier
// and faster.
//
// ### Concepts
//
// The following concepts are part of the package:
//
// - A _Token_ is a piece of information extracted from the original log message.
// It is a struct that contains fields for _TokenType_, _FieldType_, _Value_,
// and indicators of whether it's a key or value in the key=value pair.
//
// - A _TokenType_ indicates whether the token is a literal string (one that does
// not change), a variable string (one that could have different values), an IPv4
// or IPv6 address, a MAC address, an integer, a floating point number, or a
// timestamp.
//
// - A _FieldType_ indicates the semantic meaning of the token. For example, a token
// could be a source IP address (%srcipv4%), or a user (%srcuser% or %dstuser%),
// an action (%action%) or a status (%status%).
//
// - A _Sequence_ is a list of Tokens. It is returned by the _Tokenizer_, and the _Parser_.
//
// - A _Scanner_ is a sequential lexical analyzer that breaks a log message into a
// sequence of tokens. It is sequential because it goes through log message sequentially
// tokentizing each part of the message, without the use of regular expressions.
// The scanner currently recognizes time stamps, IPv4 addresses, URLs, MAC addresses,
// integers and floating point numbers.
//
// - A _Parser_ is a tree-based parsing engine for log messages. It builds a parsing
// tree based on pattern sequence supplied, and for each message sequence, returns
// the matching pattern sequence. Each of the message tokens will be marked with the
// semantic field types.
package sequence
