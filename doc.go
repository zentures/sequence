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

// Sequence is a high performance sequential log scanner, analyzer and parser.
// It sequentially goes through a log message, parses out the meaningful parts,
// without the use regular expressions. It can parse over 100,000 messages per
// second without the need to separate parsing rules by log source type.
//
// Documentation and other information are available at sequence.trustpath.com
package sequence
