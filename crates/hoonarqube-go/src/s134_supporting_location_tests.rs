//! Exact S134 supporting-location regressions.
//!
//! Original chi sources are pinned to167e1e3bd039d060696b99c8da4e876ae04f42c1.
//! The ten supplementary sources and expectations were measured independently
//! with actual `SonarGo` before this implementation. The two switch primary
//! range differences remain explicit residuals. Native coordinates are scalar.
/*
Copyright (c) 2015-present Peter Kieltyka (https://github.com/pkieltyka), Google Inc.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
use std::path::PathBuf;

use super::{AnalyzerOptions, FlowLocation, Issue, Pos, Range, analyze};

fn range([start_line, start_column, end_line, end_column]: [u32; 4]) -> Range {
    Range {
        start: Pos {
            line: start_line,
            column: start_column,
        },
        end: Pos {
            line: end_line,
            column: end_column,
        },
    }
}

fn expected(primary: [u32; 4], locations: &[[u32; 4]]) -> Issue {
    let mut issue = Issue::new(
        "go:S134",
        "Refactor this code to not nest more than 4 control flow statements.",
        range(primary),
    );
    for (index, location) in locations.iter().enumerate() {
        issue = issue.with_flow(vec![FlowLocation::in_primary_file(
            format!("Nesting depth {}", index + 1),
            range(*location),
        )]);
    }
    issue
}

fn assert_s134(source: &str, maximum: usize, mut expected: Vec<Issue>) {
    let options = AnalyzerOptions {
        maximum_nesting_depth: maximum,
        ..AnalyzerOptions::default()
    };
    for issue in &mut expected {
        issue.message =
            format!("Refactor this code to not nest more than {maximum} control flow statements.");
    }
    let report = analyze(PathBuf::from("case.go"), source, &options);
    let actual: Vec<_> = report
        .issues
        .into_iter()
        .filter(|issue| issue.rule_key == "go:S134")
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn s134_mixed_control_ancestor_keywords() {
    assert_s134(
        BOUNDARY_1,
        4,
        vec![expected(
            [10, 5, 10, 7],
            &[[4, 1, 4, 3], [5, 2, 5, 5], [6, 3, 6, 9], [8, 4, 8, 10]],
        )],
    );
}

#[test]
fn s134_for_primary_preserved() {
    assert_s134(
        BOUNDARY_2,
        4,
        vec![expected(
            [9, 5, 9, 8],
            &[[4, 1, 4, 3], [5, 2, 5, 8], [7, 3, 7, 6], [8, 4, 8, 6]],
        )],
    );
}

#[test]
fn s134_expression_switch_primary_residual_preserved() {
    assert_s134(
        BOUNDARY_3,
        4,
        vec![expected(
            [8, 5, 8, 7],
            &[[4, 1, 4, 3], [5, 2, 5, 4], [6, 3, 6, 5], [7, 4, 7, 6]],
        )],
    );
}

#[test]
fn s134_type_switch_primary_residual_preserved() {
    assert_s134(
        BOUNDARY_4,
        4,
        vec![expected(
            [8, 5, 8, 7],
            &[[4, 1, 4, 3], [5, 2, 5, 4], [6, 3, 6, 5], [7, 4, 7, 6]],
        )],
    );
}

#[test]
fn s134_else_if_uses_first_chain_keyword() {
    assert_s134(
        BOUNDARY_5,
        4,
        vec![expected(
            [12, 5, 12, 7],
            &[[4, 1, 4, 3], [5, 2, 5, 5], [6, 3, 6, 5], [9, 4, 9, 6]],
        )],
    );
}

#[test]
fn s134_function_literal_is_transparent() {
    assert_s134(
        BOUNDARY_6,
        4,
        vec![expected(
            [9, 6, 9, 8],
            &[[4, 1, 4, 3], [5, 2, 5, 5], [7, 4, 7, 6], [8, 5, 8, 7]],
        )],
    );
}

#[test]
fn s134_named_sibling_and_method_boundaries() {
    assert_s134(
        BOUNDARY_7,
        4,
        vec![expected(
            [8, 5, 8, 7],
            &[[4, 1, 4, 3], [5, 2, 5, 4], [6, 3, 6, 5], [7, 4, 7, 6]],
        )],
    );
}

#[test]
fn s134_exact_threshold_and_deeper_suppression() {
    assert_s134(
        BOUNDARY_8,
        4,
        vec![
            expected(
                [20, 5, 20, 7],
                &[
                    [16, 1, 16, 3],
                    [17, 2, 17, 4],
                    [18, 3, 18, 5],
                    [19, 4, 19, 6],
                ],
            ),
            expected(
                [34, 5, 34, 7],
                &[
                    [30, 1, 30, 3],
                    [31, 2, 31, 4],
                    [32, 3, 32, 5],
                    [33, 4, 33, 6],
                ],
            ),
        ],
    );
}

#[test]
fn s134_scalar_unicode_crlf_locations() {
    assert_s134(
        BOUNDARY_9,
        4,
        vec![expected(
            [4, 71, 4, 73],
            &[
                [4, 11, 4, 13],
                [4, 26, 4, 28],
                [4, 41, 4, 43],
                [4, 56, 4, 58],
            ],
        )],
    );
}

#[test]
fn s134_default_shallow_clean() {
    assert_s134(BOUNDARY_10, 4, vec![]);
}

#[test]
fn s134_original_chi_five_complete_issue_objects() {
    assert_s134(
        ORIGINAL_CHI,
        4,
        vec![
            expected(
                [448, 5, 448, 7],
                &[
                    [414, 1, 414, 4],
                    [428, 2, 428, 8],
                    [443, 3, 443, 6],
                    [447, 4, 447, 6],
                ],
            ),
            expected(
                [458, 5, 458, 7],
                &[
                    [414, 1, 414, 4],
                    [428, 2, 428, 8],
                    [443, 3, 443, 6],
                    [457, 4, 457, 6],
                ],
            ),
            expected(
                [471, 5, 471, 7],
                &[
                    [414, 1, 414, 4],
                    [428, 2, 428, 8],
                    [443, 3, 443, 6],
                    [470, 4, 470, 6],
                ],
            ),
            expected(
                [527, 5, 527, 7],
                &[
                    [414, 1, 414, 4],
                    [518, 2, 518, 4],
                    [519, 3, 519, 5],
                    [526, 4, 526, 7],
                ],
            ),
            expected(
                [530, 5, 530, 7],
                &[
                    [414, 1, 414, 4],
                    [518, 2, 518, 4],
                    [519, 3, 519, 5],
                    [526, 4, 526, 7],
                ],
            ),
        ],
    );
}

#[test]
fn s134_original_valid_controls_and_clean_neighbor() {
    assert_s134(
        ORIGINAL_S134_BAD,
        4,
        vec![expected(
            [3, 57, 3, 59],
            &[
                [3, 28, 3, 30],
                [3, 35, 3, 37],
                [3, 42, 3, 45],
                [3, 50, 3, 52],
            ],
        )],
    );
    assert_s134(
        ORIGINAL_S3776_BAD,
        4,
        vec![expected(
            [4, 29, 4, 31],
            &[[4, 1, 4, 3], [4, 8, 4, 10], [4, 15, 4, 17], [4, 22, 4, 24]],
        )],
    );
    assert_s134(ORIGINAL_S134_GOOD, 4, vec![]);
}

#[test]
fn s134_native_maximum_0() {
    assert_s134(BOUNDARY_10, 0, vec![expected([4, 1, 4, 3], &[])]);
}

#[test]
fn s134_native_maximum_1() {
    assert_s134(
        BOUNDARY_10,
        1,
        vec![expected([5, 2, 5, 4], &[[4, 1, 4, 3]])],
    );
}

const BOUNDARY_1: &str = r"package mixed

func MixedAncestors(value any, limit int, enabled bool) {
	if enabled {
		for index := 0; index < limit; index++ {
			switch index % 2 {
			case 0:
				switch typed := value.(type) {
				case int:
					if typed > index {
						println(typed)
					}
				default:
					println(index)
				}
			default:
				println(limit)
			}
		}
	}
}
";

const BOUNDARY_2: &str = r"package forprimary

func ForPrimary(values []int, seed int, enabled bool) {
	if enabled {
		switch seed % 2 {
		case 0:
			for _, value := range values {
				if value > seed {
					for repeat := 0; repeat < value; repeat++ {
						println(repeat)
					}
				}
			}
		default:
			println(seed)
		}
	}
}
";

const BOUNDARY_3: &str = r"package expressionprimary

func ExpressionSwitchPrimary(flags [4]bool, value int) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					switch value % 2 {
					case 0:
						println(value)
					default:
						println(-value)
					}
				}
			}
		}
	}
}
";

const BOUNDARY_4: &str = r#"package typeprimary

func TypeSwitchPrimary(flags [4]bool, value any) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					switch typed := value.(type) {
					case int:
						println(typed)
					default:
						println("other")
					}
				}
			}
		}
	}
}
"#;

const BOUNDARY_5: &str = r"package effectiveelseif

func EffectiveElseIf(mode int, flags [4]bool) {
	if flags[0] {
		for index := 0; index < 2; index++ {
			if mode == 0 {
				println(index)
			} else if mode == 1 {
				if flags[1] {
					println(mode)
				} else if flags[2] {
					if flags[3] {
						println(index)
					}
				}
			} else {
				println(mode)
			}
		}
	}
}
";

const BOUNDARY_6: &str = r"package transparentliteral

func TransparentLiteral(flags [4]bool, limit int) {
	if flags[0] {
		for index := 0; index < limit; index++ {
			func() {
				if flags[1] {
					if flags[2] {
						if flags[3] {
							println(index)
						}
					}
				}
			}()
		}
	}
}
";

const BOUNDARY_7: &str = r#"package isolation

func FirstDeep(flags [5]bool) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					if flags[4] {
						println("deep")
					}
				}
			}
		}
	}
}

func NextSibling(flags [4]bool) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					println("sibling")
				}
			}
		}
	}
}

type Guard struct {
	Enabled bool
}

func (guard Guard) NextMethod(flags [3]bool) {
	if guard.Enabled {
		if flags[0] {
			if flags[1] {
				if flags[2] {
					println("method")
				}
			}
		}
	}
}
"#;

const BOUNDARY_8: &str = r#"package threshold

func FourLevels(flags [4]bool) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					println("four")
				}
			}
		}
	}
}

func FiveLevels(flags [5]bool) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					if flags[4] {
						println("five")
					}
				}
			}
		}
	}
}

func SevenLevels(flags [7]bool) {
	if flags[0] {
		if flags[1] {
			if flags[2] {
				if flags[3] {
					if flags[4] {
						if flags[5] {
							if flags[6] {
								println("seven")
							}
						}
					}
				}
			}
		}
	}
}
"#;

const BOUNDARY_9: &str = "package unicodecrlf\r\n\r\nfunc UnicodeCRLF(value int) {\r\n\t_ = \"🦉é\"; if value > 0 { if value > 1 { if value > 2 { if value > 3 { if value > 4 { println(value) } } } } }\r\n}\r\n";

const BOUNDARY_10: &str = r"package nativeoptions

func NativeOptionsShallow(enabled bool, value int) {
	if enabled {
		if value > 0 {
			println(value)
		}
	}
}
";

const ORIGINAL_CHI: &str = r#"package chi

// Radix tree implementation below is a based on the original work by
// Armon Dadgar in https://github.com/armon/go-radix/blob/master/radix.go
// (MIT licensed). It's been heavily modified for use as a HTTP routing tree.

import (
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type methodTyp uint

const (
	mSTUB methodTyp = 1 << iota
	mCONNECT
	mDELETE
	mGET
	mHEAD
	mOPTIONS
	mPATCH
	mPOST
	mPUT
	mQUERY
	mTRACE
)

var mALL = mCONNECT | mDELETE | mGET | mHEAD |
	mOPTIONS | mPATCH | mPOST | mPUT | mQUERY | mTRACE

// methodQuery is the HTTP QUERY method (RFC 10008), a safe, idempotent
// method that conveys a request body. It is defined here until net/http
// provides an equivalent constant, at which point this is a 1-1 swap.
const methodQuery = "QUERY"

var methodMap = map[string]methodTyp{
	http.MethodConnect: mCONNECT,
	http.MethodDelete:  mDELETE,
	http.MethodGet:     mGET,
	http.MethodHead:    mHEAD,
	http.MethodOptions: mOPTIONS,
	http.MethodPatch:   mPATCH,
	http.MethodPost:    mPOST,
	http.MethodPut:     mPUT,
	methodQuery:        mQUERY,
	http.MethodTrace:   mTRACE,
}

var reverseMethodMap = map[methodTyp]string{
	mCONNECT: http.MethodConnect,
	mDELETE:  http.MethodDelete,
	mGET:     http.MethodGet,
	mHEAD:    http.MethodHead,
	mOPTIONS: http.MethodOptions,
	mPATCH:   http.MethodPatch,
	mPOST:    http.MethodPost,
	mPUT:     http.MethodPut,
	mQUERY:   methodQuery,
	mTRACE:   http.MethodTrace,
}

// RegisterMethod adds support for custom HTTP method handlers, available
// via Router#Method and Router#MethodFunc
func RegisterMethod(method string) {
	if method == "" {
		return
	}
	method = strings.ToUpper(method)
	if _, ok := methodMap[method]; ok {
		return
	}
	n := len(methodMap)
	if n > strconv.IntSize-2 {
		panic(fmt.Sprintf("chi: max number of methods reached (%d)", strconv.IntSize))
	}
	mt := methodTyp(2 << n)
	methodMap[method] = mt
	reverseMethodMap[mt] = method
	mALL |= mt
}

type nodeTyp uint8

const (
	ntStatic   nodeTyp = iota // /home
	ntRegexp                  // /{id:[0-9]+}
	ntParam                   // /{user}
	ntCatchAll                // /api/v1/*
)

type node struct {
	// subroutes on the leaf node
	subroutes Routes

	// regexp matcher for regexp nodes
	rex *regexp.Regexp

	// HTTP handler endpoints on the leaf node
	endpoints endpoints

	// prefix is the common prefix we ignore
	prefix string

	// child nodes should be stored in-order for iteration,
	// in groups of the node type.
	children [ntCatchAll + 1]nodes

	// first byte of the child prefix
	tail byte

	// node type: static, regexp, param, catchAll
	typ nodeTyp

	// first byte of the prefix
	label byte
}

// endpoints is a mapping of http method constants to handlers
// for a given route.
type endpoints map[methodTyp]*endpoint

type endpoint struct {
	// endpoint handler
	handler http.Handler

	// pattern is the routing pattern for handler nodes
	pattern string

	// parameter keys recorded on handler nodes
	paramKeys []string
}

func (s endpoints) Value(method methodTyp) *endpoint {
	mh, ok := s[method]
	if !ok {
		mh = &endpoint{}
		s[method] = mh
	}
	return mh
}

func (n *node) InsertRoute(method methodTyp, pattern string, handler http.Handler) *node {
	var parent *node
	search := pattern

	for {
		// Handle key exhaustion
		if len(search) == 0 {
			// Insert or update the node's leaf handler
			n.setEndpoint(method, handler, pattern)
			return n
		}

		// We're going to be searching for a wild node next,
		// in this case, we need to get the tail
		var label = search[0]
		var segTail byte
		var segEndIdx int
		var segTyp nodeTyp
		var segRexpat string
		if label == '{' || label == '*' {
			segTyp, _, segRexpat, segTail, _, segEndIdx = patNextSegment(search)
		}

		var prefix string
		if segTyp == ntRegexp {
			prefix = segRexpat
		}

		// Look for the edge to attach to
		parent = n
		n = n.getEdge(segTyp, label, segTail, prefix)

		// No edge, create one
		if n == nil {
			child := &node{label: label, tail: segTail, prefix: search}
			hn := parent.addChild(child, search)
			hn.setEndpoint(method, handler, pattern)

			return hn
		}

		// Found an edge to match the pattern

		if n.typ > ntStatic {
			// We found a param node, trim the param from the search path and continue.
			// This param/wild pattern segment would already be on the tree from a previous
			// call to addChild when creating a new node.
			search = search[segEndIdx:]
			continue
		}

		// Static nodes fall below here.
		// Determine longest prefix of the search key on match.
		commonPrefix := longestPrefix(search, n.prefix)
		if commonPrefix == len(n.prefix) {
			// the common prefix is as long as the current node's prefix we're attempting to insert.
			// keep the search going.
			search = search[commonPrefix:]
			continue
		}

		// Split the node
		child := &node{
			typ:    ntStatic,
			prefix: search[:commonPrefix],
		}
		parent.replaceChild(search[0], segTail, child)

		// Restore the existing node
		n.label = n.prefix[commonPrefix]
		n.prefix = n.prefix[commonPrefix:]
		child.addChild(n, n.prefix)

		// If the new key is a subset, set the method/handler on this node and finish.
		search = search[commonPrefix:]
		if len(search) == 0 {
			child.setEndpoint(method, handler, pattern)
			return child
		}

		// Create a new edge for the node
		subchild := &node{
			typ:    ntStatic,
			label:  search[0],
			prefix: search,
		}
		hn := child.addChild(subchild, search)
		hn.setEndpoint(method, handler, pattern)
		return hn
	}
}

// addChild appends the new `child` node to the tree using the `pattern` as the trie key.
// For a URL router like chi's, we split the static, param, regexp and wildcard segments
// into different nodes. In addition, addChild will recursively call itself until every
// pattern segment is added to the url pattern tree as individual nodes, depending on type.
func (n *node) addChild(child *node, prefix string) *node {
	search := prefix

	// handler leaf node added to the tree is the child.
	// this may be overridden later down the flow
	hn := child

	// Parse next segment
	segTyp, _, segRexpat, segTail, segStartIdx, segEndIdx := patNextSegment(search)

	// Add child depending on next up segment
	switch segTyp {

	case ntStatic:
		// Search prefix is all static (that is, has no params in path)
		// noop

	default:
		// Search prefix contains a param, regexp or wildcard

		if segTyp == ntRegexp {
			rex, err := regexp.Compile(segRexpat)
			if err != nil {
				panic(fmt.Sprintf("chi: invalid regexp pattern '%s' in route param", segRexpat))
			}
			child.prefix = segRexpat
			child.rex = rex
		}

		if segStartIdx == 0 {
			// Route starts with a param
			child.typ = segTyp

			if segTyp == ntCatchAll {
				segStartIdx = -1
			} else {
				segStartIdx = segEndIdx
			}
			if segStartIdx < 0 {
				segStartIdx = len(search)
			}
			child.tail = segTail // for params, we set the tail

			if segStartIdx != len(search) {
				// add static edge for the remaining part, split the end.
				// its not possible to have adjacent param nodes, so its certainly
				// going to be a static node next.

				search = search[segStartIdx:] // advance search position

				nn := &node{
					typ:    ntStatic,
					label:  search[0],
					prefix: search,
				}
				hn = child.addChild(nn, search)
			}

		} else if segStartIdx > 0 {
			// Route has some param

			// starts with a static segment
			child.typ = ntStatic
			child.prefix = search[:segStartIdx]
			child.rex = nil

			// add the param edge node
			search = search[segStartIdx:]

			nn := &node{
				typ:   segTyp,
				label: search[0],
				tail:  segTail,
			}
			hn = child.addChild(nn, search)

		}
	}

	n.children[child.typ] = append(n.children[child.typ], child)
	n.children[child.typ].Sort()
	return hn
}

func (n *node) replaceChild(label, tail byte, child *node) {
	for i := 0; i < len(n.children[child.typ]); i++ {
		if n.children[child.typ][i].label == label && n.children[child.typ][i].tail == tail {
			n.children[child.typ][i] = child
			n.children[child.typ][i].label = label
			n.children[child.typ][i].tail = tail
			return
		}
	}
	panic("chi: replacing missing child")
}

func (n *node) getEdge(ntyp nodeTyp, label, tail byte, prefix string) *node {
	nds := n.children[ntyp]
	for i := range nds {
		if nds[i].label == label && nds[i].tail == tail {
			if ntyp == ntRegexp && nds[i].prefix != prefix {
				continue
			}
			return nds[i]
		}
	}
	return nil
}

func (n *node) setEndpoint(method methodTyp, handler http.Handler, pattern string) {
	// Set the handler for the method type on the node
	if n.endpoints == nil {
		n.endpoints = make(endpoints)
	}

	paramKeys := patParamKeys(pattern)

	if method&mSTUB == mSTUB {
		n.endpoints.Value(mSTUB).handler = handler
	}
	if method&mALL == mALL {
		h := n.endpoints.Value(mALL)
		h.handler = handler
		h.pattern = pattern
		h.paramKeys = paramKeys
		for _, m := range methodMap {
			h := n.endpoints.Value(m)
			h.handler = handler
			h.pattern = pattern
			h.paramKeys = paramKeys
		}
	} else {
		h := n.endpoints.Value(method)
		h.handler = handler
		h.pattern = pattern
		h.paramKeys = paramKeys
	}
}

func (n *node) FindRoute(rctx *Context, method methodTyp, path string) (*node, endpoints, http.Handler) {
	// Reset the context routing pattern and params
	rctx.routePattern = ""
	rctx.routeParams.Keys = rctx.routeParams.Keys[:0]
	rctx.routeParams.Values = rctx.routeParams.Values[:0]

	// Find the routing handlers for the path
	rn := n.findRoute(rctx, method, path)
	if rn == nil {
		return nil, nil, nil
	}

	// Record the routing params in the request lifecycle
	rctx.URLParams.Keys = append(rctx.URLParams.Keys, rctx.routeParams.Keys...)
	rctx.URLParams.Values = append(rctx.URLParams.Values, rctx.routeParams.Values...)

	// Record the routing pattern in the request lifecycle
	if rn.endpoints[method].pattern != "" {
		rctx.routePattern = rn.endpoints[method].pattern
		rctx.RoutePatterns = append(rctx.RoutePatterns, rctx.routePattern)
	}

	return rn, rn.endpoints, rn.endpoints[method].handler
}

// Recursive edge traversal by checking all nodeTyp groups along the way.
// It's like searching through a multi-dimensional radix trie.
func (n *node) findRoute(rctx *Context, method methodTyp, path string) *node {
	nn := n
	search := path

	for t, nds := range nn.children {
		ntyp := nodeTyp(t)
		if len(nds) == 0 {
			continue
		}

		var xn *node
		xsearch := search

		var label byte
		if search != "" {
			label = search[0]
		}

		switch ntyp {
		case ntStatic:
			xn = nds.findEdge(label)
			if xn == nil || !strings.HasPrefix(xsearch, xn.prefix) {
				continue
			}
			xsearch = xsearch[len(xn.prefix):]

		case ntParam, ntRegexp:
			// short-circuit and return no matching route for empty param values
			if xsearch == "" {
				continue
			}

			// serially loop through each node grouped by the tail delimiter
			for _, xn = range nds {
				// label for param nodes is the delimiter byte
				p := strings.IndexByte(xsearch, xn.tail)

				if p < 0 {
					if xn.tail == '/' {
						p = len(xsearch)
					} else {
						continue
					}
				} else if ntyp == ntRegexp && p == 0 {
					continue
				}

				if ntyp == ntRegexp && xn.rex != nil {
					if !xn.rex.MatchString(xsearch[:p]) {
						continue
					}
				} else if strings.IndexByte(xsearch[:p], '/') != -1 {
					// avoid a match across path segments
					continue
				}

				prevlen := len(rctx.routeParams.Values)
				rctx.routeParams.Values = append(rctx.routeParams.Values, xsearch[:p])
				xsearch = xsearch[p:]

				if len(xsearch) == 0 {
					if xn.isLeaf() {
						h := xn.endpoints[method]
						if h != nil && h.handler != nil {
							rctx.routeParams.Keys = append(rctx.routeParams.Keys, h.paramKeys...)
							return xn
						}

						for endpoints := range xn.endpoints {
							if endpoints == mALL || endpoints == mSTUB {
								continue
							}
							if !slices.Contains(rctx.methodsAllowed, endpoints) {
								rctx.methodsAllowed = append(rctx.methodsAllowed, endpoints)
							}
						}

						// flag that the routing context found a route, but not a corresponding
						// supported method
						rctx.methodNotAllowed = true
					}
				}

				// recursively find the next node on this branch
				fin := xn.findRoute(rctx, method, xsearch)
				if fin != nil {
					return fin
				}

				// not found on this branch, reset vars
				rctx.routeParams.Values = rctx.routeParams.Values[:prevlen]
				xsearch = search
			}

			rctx.routeParams.Values = append(rctx.routeParams.Values, "")

		default:
			// catch-all nodes
			rctx.routeParams.Values = append(rctx.routeParams.Values, search)
			xn = nds[0]
			xsearch = ""
		}

		if xn == nil {
			continue
		}

		// did we find it yet?
		if len(xsearch) == 0 {
			if xn.isLeaf() {
				h := xn.endpoints[method]
				if h != nil && h.handler != nil {
					rctx.routeParams.Keys = append(rctx.routeParams.Keys, h.paramKeys...)
					return xn
				}

				for endpoints := range xn.endpoints {
					if endpoints == mALL || endpoints == mSTUB {
						continue
					}
					if !slices.Contains(rctx.methodsAllowed, endpoints) {
						rctx.methodsAllowed = append(rctx.methodsAllowed, endpoints)
					}
				}

				// flag that the routing context found a route, but not a corresponding
				// supported method
				rctx.methodNotAllowed = true
			}
		}

		// recursively find the next node..
		fin := xn.findRoute(rctx, method, xsearch)
		if fin != nil {
			return fin
		}

		// Did not find final handler, let's remove the param here if it was set
		if xn.typ > ntStatic {
			if len(rctx.routeParams.Values) > 0 {
				rctx.routeParams.Values = rctx.routeParams.Values[:len(rctx.routeParams.Values)-1]
			}
		}

	}

	return nil
}

func (n *node) findEdge(ntyp nodeTyp, label byte) *node {
	nds := n.children[ntyp]
	num := len(nds)
	idx := 0

	switch ntyp {
	case ntStatic, ntParam, ntRegexp:
		i, j := 0, num-1
		for i <= j {
			idx = i + (j-i)/2
			if label > nds[idx].label {
				i = idx + 1
			} else if label < nds[idx].label {
				j = idx - 1
			} else {
				i = num // breaks cond
			}
		}
		if nds[idx].label != label {
			return nil
		}
		return nds[idx]

	default: // catch all
		return nds[idx]
	}
}

func (n *node) isLeaf() bool {
	return n.endpoints != nil
}

func (n *node) findPattern(pattern string) bool {
	nn := n
	for _, nds := range nn.children {
		if len(nds) == 0 {
			continue
		}

		n = nn.findEdge(nds[0].typ, pattern[0])
		if n == nil {
			continue
		}

		var idx int
		var xpattern string

		switch n.typ {
		case ntStatic:
			idx = longestPrefix(pattern, n.prefix)
			if idx < len(n.prefix) {
				continue
			}

		case ntParam, ntRegexp:
			idx = strings.IndexByte(pattern, '}') + 1

		case ntCatchAll:
			idx = longestPrefix(pattern, "*")

		default:
			panic("chi: unknown node type")
		}

		xpattern = pattern[idx:]
		if len(xpattern) == 0 {
			return true
		}

		return n.findPattern(xpattern)
	}
	return false
}

func (n *node) routes() []Route {
	rts := []Route{}

	n.walk(func(eps endpoints, subroutes Routes) bool {
		// Hide Mount()'s stub handler, but not a real handler sharing its pattern.
		var stubHandler http.Handler
		if eps[mSTUB] != nil {
			stubHandler = eps[mSTUB].handler
		}

		// Group methodHandlers by unique patterns
		pats := make(map[string]endpoints)

		for mt, h := range eps {
			if h.pattern == "" {
				continue
			}
			p, ok := pats[h.pattern]
			if !ok {
				p = endpoints{}
				pats[h.pattern] = p
			}
			p[mt] = h
		}

		for p, mh := range pats {
			hs := make(map[string]http.Handler)

			// Walk() reads Handlers["*"] for With() middleware when recursing
			// into a subroute, so keep it there even if it's also the stub.
			if mh[mALL] != nil && mh[mALL].handler != nil {
				if subroutes != nil || !equalHandlers(mh[mALL].handler, stubHandler) {
					hs["*"] = mh[mALL].handler
				}
			}

			for mt, h := range mh {
				if h.handler == nil || equalHandlers(h.handler, stubHandler) {
					continue
				}
				if m, ok := reverseMethodMap[mt]; ok {
					hs[m] = h.handler
				}
			}

			// Keep subroute nodes so Walk() can recurse; a stub-only leaf has nothing to report.
			if len(hs) == 0 && subroutes == nil {
				continue
			}

			rt := Route{subroutes, hs, p}
			rts = append(rts, rt)
		}

		return false
	})

	return rts
}

// equalHandlers reports whether a and b are the same handler value. Handlers
// are commonly funcs (e.g. http.HandlerFunc), and a direct == on those
// panics at runtime, so funcs are compared by pointer instead.
func equalHandlers(a, b http.Handler) bool {
	if a == nil || b == nil {
		return a == b
	}

	av := reflect.ValueOf(a)
	bv := reflect.ValueOf(b)
	if av.Type() != bv.Type() {
		return false
	}

	if av.Kind() == reflect.Func {
		return av.Pointer() == bv.Pointer()
	}
	if av.Type().Comparable() {
		return a == b
	}
	return false
}

func (n *node) walk(fn func(eps endpoints, subroutes Routes) bool) bool {
	// Visit the leaf values if any
	if (n.endpoints != nil || n.subroutes != nil) && fn(n.endpoints, n.subroutes) {
		return true
	}

	// Recurse on the children
	for _, ns := range n.children {
		for _, cn := range ns {
			if cn.walk(fn) {
				return true
			}
		}
	}
	return false
}

// patNextSegment returns the next segment details from a pattern:
// node type, param key, regexp string, param tail byte, param starting index, param ending index
func patNextSegment(pattern string) (nodeTyp, string, string, byte, int, int) {
	ps := strings.Index(pattern, "{")
	ws := strings.Index(pattern, "*")

	if ps < 0 && ws < 0 {
		return ntStatic, "", "", 0, 0, len(pattern) // we return the entire thing
	}

	// Sanity check
	if ps >= 0 && ws >= 0 && ws < ps {
		panic("chi: wildcard '*' must be the last pattern in a route, otherwise use a '{param}'")
	}

	var tail byte = '/' // Default endpoint tail to / byte

	if ps >= 0 {
		// Param/Regexp pattern is next
		nt := ntParam

		// Read to closing } taking into account opens and closes in curl count (cc)
		cc := 0
		pe := ps
		for i, c := range pattern[ps:] {
			if c == '{' {
				cc++
			} else if c == '}' {
				cc--
				if cc == 0 {
					pe = ps + i
					break
				}
			}
		}
		if pe == ps {
			panic("chi: route param closing delimiter '}' is missing")
		}

		key := pattern[ps+1 : pe]
		pe++ // set end to next position

		if pe < len(pattern) {
			tail = pattern[pe]
		}

		key, rexpat, isRegexp := strings.Cut(key, ":")
		if isRegexp {
			nt = ntRegexp
		}

		if len(rexpat) > 0 {
			if rexpat[0] != '^' {
				rexpat = "^" + rexpat
			}
			if rexpat[len(rexpat)-1] != '$' {
				rexpat += "$"
			}
		}

		return nt, key, rexpat, tail, ps, pe
	}

	// Wildcard pattern as finale
	if ws < len(pattern)-1 {
		panic("chi: wildcard '*' must be the last value in a route. trim trailing text or use a '{param}' instead")
	}
	return ntCatchAll, "*", "", 0, ws, len(pattern)
}

func patParamKeys(pattern string) []string {
	pat := pattern
	paramKeys := []string{}
	for {
		ptyp, paramKey, _, _, _, e := patNextSegment(pat)
		if ptyp == ntStatic {
			return paramKeys
		}
		for i := 0; i < len(paramKeys); i++ {
			if paramKeys[i] == paramKey {
				panic(fmt.Sprintf("chi: routing pattern '%s' contains duplicate param key, '%s'", pattern, paramKey))
			}
		}
		paramKeys = append(paramKeys, paramKey)
		pat = pat[e:]
	}
}

// longestPrefix finds the length of the shared prefix of two strings
func longestPrefix(k1, k2 string) (i int) {
	for i = 0; i < min(len(k1), len(k2)); i++ {
		if k1[i] != k2[i] {
			break
		}
	}
	return
}

type nodes []*node

// Sort the list of nodes by label
func (ns nodes) Sort()              { sort.Sort(ns); ns.tailSort() }
func (ns nodes) Len() int           { return len(ns) }
func (ns nodes) Swap(i, j int)      { ns[i], ns[j] = ns[j], ns[i] }
func (ns nodes) Less(i, j int) bool { return ns[i].label < ns[j].label }

// tailSort pushes nodes with '/' as the tail to the end of the list for param nodes.
// The list order determines the traversal order.
func (ns nodes) tailSort() {
	for i, n := range slices.Backward(ns) {
		if n.typ > ntStatic && n.tail == '/' {
			ns.Swap(i, len(ns)-1)
			return
		}
	}
}

func (ns nodes) findEdge(label byte) *node {
	num := len(ns)
	idx := 0
	i, j := 0, num-1
	for i <= j {
		idx = i + (j-i)/2
		if label > ns[idx].label {
			i = idx + 1
		} else if label < ns[idx].label {
			j = idx - 1
		} else {
			i = num // breaks cond
		}
	}
	if ns[idx].label != label {
		return nil
	}
	return ns[idx]
}

// Route describes the details of a routing handler.
// Handlers map key is an HTTP method
type Route struct {
	SubRoutes Routes
	Handlers  map[string]http.Handler
	Pattern   string
}

// WalkFunc is the type of the function called for each method and route visited by Walk.
type WalkFunc func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error

// Walk walks any router tree that implements Routes interface.
func Walk(r Routes, walkFn WalkFunc) error {
	return walk(r, walkFn, "")
}

func walk(r Routes, walkFn WalkFunc, parentRoute string, parentMw ...func(http.Handler) http.Handler) error {
	for _, route := range r.Routes() {
		mws := slices.Concat(parentMw, r.Middlewares())

		if route.SubRoutes != nil {
			if handler, ok := route.Handlers["*"]; ok {
				if chain, ok := handler.(*ChainHandler); ok {
					mws = append(mws, chain.Middlewares...)
				}
			}

			if err := walk(route.SubRoutes, walkFn, parentRoute+route.Pattern, mws...); err != nil {
				return err
			}
			continue
		}

		for method, handler := range route.Handlers {
			if method == "*" {
				// Ignore a "catchAll" method, since we pass down all the specific methods for each route.
				continue
			}

			fullRoute := parentRoute + route.Pattern
			fullRoute = strings.ReplaceAll(fullRoute, "/*/", "/")

			if chain, ok := handler.(*ChainHandler); ok {
				if err := walkFn(method, fullRoute, chain.Endpoint, append(mws, chain.Middlewares...)...); err != nil {
					return err
				}
			} else {
				if err := walkFn(method, fullRoute, handler, mws...); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
"#;

const ORIGINAL_S134_BAD: &str = r"// Hoonarqube oracle fixture: go:S134 bad
package oracle
func deep(a,b,c,d,e bool) { if a { if b { for c { if d { if e { println(1) } } } } } }
";

const ORIGINAL_S3776_BAD: &str = r"// Hoonarqube oracle fixture: go:S3776 bad
package oracle
func complex(a,b,c,d,e bool) {
 if a { if b { if c { if d { if e { println(1) } } } } }
 if a && b && c && d { println(2) }
}
";

const ORIGINAL_S134_GOOD: &str = r#"// Hoonarqube oracle fixture: go:S134 good
package oracle

func nestedFlow(condition1, condition2, condition4, condition5 bool) {
	if !condition1 {
		return
	}
	if !condition2 {
		return
	}
	for i := 1; i <= 10; i++ {
		println(i)
		if condition4 {
			if condition5 {
				println("nested")
			}
			return
		}
	}
}
"#;
