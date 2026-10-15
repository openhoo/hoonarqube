//! CLI regression for selected-snapshot Go error guards.
//!
//! Mux sources are from gorilla/mux db9d1d0073d27a0a2d9a8c1bc52aa0af4374d265.
//! The embedded complete reports preserve the admitted SonarGo 1.43.0.7704
//! evidence and explicit two-function prediction. Conservative refusal controls
//! below qualify native behavior; they do not claim new Sonar equivalence.
// The embedded gorilla/mux sources retain their upstream license:
/*
Copyright (c) 2023 The Gorilla Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

     * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
     * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use hoonarqube_core::{AnalyzerOptions, RuleProfile};
use serde_json::Value;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-go-s3776-project-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn write(&self, name: &str, source: &str) {
        let path = self.0.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
    }

    fn run(&self, label: &str, format: &str, paths: &[&str], extra: &[&str]) -> Output {
        let output = Command::new(env!("CARGO_BIN_EXE_hoonarqube"))
            .current_dir(&self.0)
            .args(["analyze", "--profile", "strict", "--format", format])
            .args(extra)
            .arg("--")
            .args(paths)
            .output()
            .unwrap();
        // Optional exact raw evidence for the parent campaign; never skips tests.
        if let Some(capture) = std::env::var_os("HOONARQUBE_REGRESSION_CAPTURE") {
            let capture = PathBuf::from(capture);
            std::fs::create_dir_all(&capture).unwrap();
            std::fs::write(
                capture.join(format!("{label}-{format}.stdout")),
                &output.stdout,
            )
            .unwrap();
            std::fs::write(
                capture.join(format!("{label}-{format}.stderr")),
                &output.stderr,
            )
            .unwrap();
        }
        output
    }

    fn document(&self, label: &str, format: &str, paths: &[&str], extra: &[&str]) -> Value {
        document(&self.run(label, format, paths, extra), 0)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn document(output: &Output, exit: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(exit),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("complete JSON document")
}

fn issue<'a>(report: &'a Value, file: &str) -> &'a Value {
    report["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["path"].as_str().unwrap().ends_with(file))
        .unwrap()["issues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["rule_key"] == "go:S3776")
        .unwrap()
}

fn assert_score(report: &Value, file: &str, score: usize) {
    assert_eq!(
        issue(report, file)["message"],
        format!(
            "Refactor this method to reduce its Cognitive Complexity from {score} to the 15 allowed."
        )
    );
}

fn caller(separator: &str) -> String {
    let mut source =
        String::from("package sample\n// 😀 target receipt\nfunc inspect(flag bool) {\n");
    for _ in 0..16 {
        source.push_str(" if flag { println(flag) }\n");
    }
    source.push_str(" _, problem := supply()\n if problem != nil { println(problem) }\n}\n");
    source.replace('\n', separator)
}

const HELPER: &str = "package sample\nfunc supply() (int, error) { return 0, nil }\n";
const NONERROR: &str = "package sample\nfunc supply() (int, *int) { return 0, nil }\n";

fn expected_artificial(files: &[(&str, &str)], contextual: bool) -> Value {
    let options = AnalyzerOptions {
        profile: RuleProfile::Strict,
        ..AnalyzerOptions::default()
    };
    let mut inputs = Vec::new();
    for &(name, source) in files {
        let mut file = hoonarqube_core::project::analyze_project_file(
            Path::new(name),
            source,
            &options,
            hoonarqube_ir::FileClassification::Source,
            false,
        );
        if contextual && name.ends_with("unusual.go") {
            let report = file.report.as_mut().unwrap();
            let finding = report
                .issues
                .iter_mut()
                .find(|i| i.rule_key == "go:S3776")
                .unwrap();
            assert!(
                finding.message.contains("from 17 to"),
                "independent file-local baseline"
            );
            finding.message = "Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.".to_owned();
            let guard_line = u32::try_from(
                source
                    .lines()
                    .position(|line| line.contains("if problem"))
                    .unwrap()
                    + 1,
            )
            .unwrap();
            assert_eq!(
                finding
                    .flows
                    .iter()
                    .filter(|flow| flow.locations[0].range.start.line == guard_line)
                    .count(),
                1
            );
            finding
                .flows
                .retain(|flow| flow.locations[0].range.start.line != guard_line);
        }
        inputs.push(file);
    }
    serde_json::to_value(
        hoonarqube_core::project::build_project_report(
            inputs,
            vec![PathBuf::from(".")],
            Vec::new(),
            &hoonarqube_core::DuplicationOptions::default(),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn s3776_project_real_mux_complete_issues() {
    let fixture = Fixture::new();
    for &(name, source) in MUX_SOURCES {
        fixture.write(name, source);
    }
    let expected_native: Value = serde_json::from_str(MUX_NATIVE).unwrap();
    // Excluded files remain inventoried, and their contents cannot contribute.
    for file in expected_native["project"]["files"].as_array().unwrap() {
        if file["classification"] == "excluded" {
            fixture.write(
                file["path"].as_str().unwrap(),
                "package mux\nfunc poison() { RegexpCompileFunc = nil }\n",
            );
        }
    }
    let native = fixture.document("real-mux", "json", &["."], &["--exclude", "**/*_test.go"]);
    let generic = fixture.document("real-mux", "sonar", &["."], &["--exclude", "**/*_test.go"]);
    let expected_generic: Value = serde_json::from_str(MUX_GENERIC).unwrap();
    let changes: Vec<_> = native["files"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|f| {
            f["issues"].as_array().unwrap().iter().filter_map(move |i| {
                if i["rule_key"] == "go:S3776"
                    && ((f["path"] == "./regexp.go" && i["range"]["start"]["line"] == 41)
                        || (f["path"] == "./route.go" && i["range"]["start"]["line"] == 247))
                {
                    Some((f["path"].clone(), i.clone()))
                } else {
                    None
                }
            })
        })
        .collect();
    assert!(
        native == expected_native,
        "complete mux report mismatch; expected regexp.go41=22 removing only133+1, route.go247=18 removing only263/267/273/280(+1,+2,+3,+3), retaining248+1; actual={changes:?}"
    );
    assert_eq!(generic, expected_generic, "complete Generic report");
    for &(name, source) in MUX_SOURCES {
        assert_eq!(
            std::fs::read(fixture.0.join(name)).unwrap(),
            source.as_bytes()
        );
    }
}

#[test]
fn go_s3776_cli_cache_tracks_sibling_sources() {
    let fixture = Fixture::new();
    let target = caller("\n");
    fixture.write("unusual.go", &target);
    for (step, content, name, flags, expected) in [
        ("initial", Some(HELPER), "helper.go", Vec::new(), 16),
        ("unchanged", Some(HELPER), "helper.go", Vec::new(), 16),
        ("signature", Some(NONERROR), "helper.go", Vec::new(), 17),
        ("delete", None, "helper.go", Vec::new(), 17),
        ("add", Some(HELPER), "helper.go", Vec::new(), 16),
        ("path", Some(HELPER), "nested/helper.go", Vec::new(), 17),
        (
            "foreign",
            Some("package other\nfunc supply() (int,error) {return 0,nil}\n"),
            "helper.go",
            Vec::new(),
            17,
        ),
        ("restore", Some(HELPER), "helper.go", Vec::new(), 16),
        (
            "test",
            Some(HELPER),
            "helper.go",
            vec!["--test-include", "helper.go"],
            17,
        ),
        (
            "build",
            Some("//go:build linux\n\npackage sample\nfunc supply() (int,error) {return 0,nil}\n"),
            "helper.go",
            Vec::new(),
            17,
        ),
    ] {
        for old in ["helper.go", "nested/helper.go"] {
            let path = fixture.0.join(old);
            if path.exists() {
                std::fs::remove_file(path).unwrap();
            }
        }
        if let Some(content) = content {
            fixture.write(name, content);
        }
        let mut warm_flags = flags.clone();
        warm_flags.extend(["--cache-dir", "cache"]);
        let warm = fixture.document(step, "json", &["."], &warm_flags);
        let cold = fixture.document(&format!("{step}-cold"), "json", &["."], &flags);
        assert_eq!(warm, cold, "full cache document after {step}");
        assert_score(&warm, "unusual.go", expected);
        assert_eq!(
            std::fs::read(fixture.0.join("unusual.go")).unwrap(),
            target.as_bytes()
        );
    }
}

#[test]
fn go_s3776_cli_context_complete_reports() {
    for (label, separator) in [("lf", "\n"), ("crlf", "\r\n")] {
        let fixture = Fixture::new();
        let target = caller(separator);
        fixture.write("unusual.go", &target);
        fixture.write("helper.go", HELPER);
        let files = [("./unusual.go", target.as_str()), ("./helper.go", HELPER)];
        let native = fixture.document(label, "json", &["."], &[]);
        assert_eq!(
            native,
            expected_artificial(&files, true),
            "full native {label}"
        );
        let generic = fixture.document(label, "sonar", &["."], &[]);
        let repeat = fixture.document(
            &format!("{label}-warm"),
            "sonar",
            &["."],
            &["--cache-dir", "cache"],
        );
        assert_eq!(generic, repeat, "full Generic {label}");
        let cognitive = generic["issues"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["ruleId"] == "go:S3776")
            .unwrap();
        assert_eq!(
            cognitive["primaryLocation"]["message"],
            issue(&native, "unusual.go")["message"]
        );
        assert_eq!(
            cognitive["secondaryLocations"].as_array().unwrap().len(),
            16
        );
        fixture.write("helper.go", "package sample\nfunc broken( {\n");
        let malformed = fixture.run(&format!("{label}-malformed"), "json", &["."], &[]);
        let malformed = document(&malformed, 2);
        assert_eq!(malformed["project"]["complete"], false);
        assert_score(&malformed, "unusual.go", 17);
        assert!(malformed["files"].as_array().unwrap().iter().any(|f| {
            f["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["rule_key"] == "go:S2260")
        }));
        assert_eq!(
            std::fs::read(fixture.0.join("unusual.go")).unwrap(),
            target.as_bytes()
        );
    }
}

#[test]
fn go_s3776_cli_selected_inventory_has_no_sibling_discovery() {
    let fixture = Fixture::new();
    let target = caller("\n");
    fixture.write("unusual.go", &target);
    let before = fixture.document("only-target", "json", &["unusual.go"], &[]);
    assert_score(&before, "unusual.go", 17);
    fixture.write("helper.go", HELPER);
    fixture.write(
        "poison.go",
        "package sample\ntype error *int\nfunc supply() *int {return nil}\n",
    );
    assert_eq!(
        before,
        fixture.document("only-target-adjacent", "json", &["unusual.go"], &[])
    );
    let selected = fixture.document("explicit-two", "json", &["unusual.go", "helper.go"], &[]);
    assert_score(&selected, "unusual.go", 16);
    let excluded = fixture.document(
        "excluded-poison",
        "json",
        &["."],
        &["--exclude", "poison.go"],
    );
    assert_score(&excluded, "unusual.go", 16);
    let only = fixture.document(
        "excluded-helper",
        "json",
        &["."],
        &["--exclude", "poison.go", "--exclude", "helper.go"],
    );
    assert_score(&only, "unusual.go", 17);
}

#[test]
fn go_s3776_cli_file_local_compatibility_and_retained_controls() {
    let fixture = Fixture::new();
    for &(name, source) in FILE_LOCAL_SOURCES {
        fixture.write(name, source);
    }
    for (format, expected) in [("json", FILE_LOCAL_NATIVE), ("sonar", FILE_LOCAL_GENERIC)] {
        let actual = fixture.document("file-local-controls", format, &["src"], &[]);
        assert_eq!(
            actual,
            serde_json::from_str::<Value>(expected).unwrap(),
            "all11 retained full controls {format}"
        );
        assert_eq!(
            actual,
            fixture.document(
                "file-local-controls-warm",
                format,
                &["src"],
                &["--cache-dir", "cache"]
            )
        );
    }
    for &(name, source) in FILE_LOCAL_SOURCES {
        assert_eq!(
            std::fs::read(fixture.0.join(name)).unwrap(),
            source.as_bytes()
        );
    }
    let clean = Fixture::new();
    clean.write(
        "clean.go",
        "package clean\nfunc answer() int { return 42 }\n",
    );
    let report = clean.document("clean", "json", &["."], &[]);
    assert_eq!(report["project"]["complete"], true);
    assert!(report["files"][0]["issues"].as_array().unwrap().is_empty());
}

// Exact pinned source bytes and complete expected documents.
const MUX_SOURCES: &[(&str, &str)] = &[
    (
        "doc.go",
        r#"// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package mux implements a request router and dispatcher.

The name mux stands for "HTTP request multiplexer". Like the standard
http.ServeMux, mux.Router matches incoming requests against a list of
registered routes and calls a handler for the route that matches the URL
or other conditions. The main features are:

  - Requests can be matched based on URL host, path, path prefix, schemes,
    header and query values, HTTP methods or using custom matchers.
  - URL hosts, paths and query values can have variables with an optional
    regular expression.
  - Registered URLs can be built, or "reversed", which helps maintaining
    references to resources.
  - Routes can be used as subrouters: nested routes are only tested if the
    parent route matches. This is useful to define groups of routes that
    share common conditions like a host, a path prefix or other repeated
    attributes. As a bonus, this optimizes request matching.
  - It implements the http.Handler interface so it is compatible with the
    standard http.ServeMux.

Let's start registering a couple of URL paths and handlers:

	func main() {
		r := mux.NewRouter()
		r.HandleFunc("/", HomeHandler)
		r.HandleFunc("/products", ProductsHandler)
		r.HandleFunc("/articles", ArticlesHandler)
		http.Handle("/", r)
	}

Here we register three routes mapping URL paths to handlers. This is
equivalent to how http.HandleFunc() works: if an incoming request URL matches
one of the paths, the corresponding handler is called passing
(http.ResponseWriter, *http.Request) as parameters.

Paths can have variables. They are defined using the format {name} or
{name:pattern}. If a regular expression pattern is not defined, the matched
variable will be anything until the next slash. For example:

	r := mux.NewRouter()
	r.HandleFunc("/products/{key}", ProductHandler)
	r.HandleFunc("/articles/{category}/", ArticlesCategoryHandler)
	r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler)

Groups can be used inside patterns, as long as they are non-capturing (?:re). For example:

	r.HandleFunc("/articles/{category}/{sort:(?:asc|desc|new)}", ArticlesCategoryHandler)

The names are used to create a map of route variables which can be retrieved
calling mux.Vars():

	vars := mux.Vars(request)
	category := vars["category"]

Note that if any capturing groups are present, mux will panic() during parsing. To prevent
this, convert any capturing groups to non-capturing, e.g. change "/{sort:(asc|desc)}" to
"/{sort:(?:asc|desc)}". This is a change from prior versions which behaved unpredictably
when capturing groups were present.

And this is all you need to know about the basic usage. More advanced options
are explained below.

Routes can also be restricted to a domain or subdomain. Just define a host
pattern to be matched. They can also have variables:

	r := mux.NewRouter()
	// Only matches if domain is "www.example.com".
	r.Host("www.example.com")
	// Matches a dynamic subdomain.
	r.Host("{subdomain:[a-z]+}.domain.com")

There are several other matchers that can be added. To match path prefixes:

	r.PathPrefix("/products/")

...or HTTP methods:

	r.Methods("GET", "POST")

...or URL schemes:

	r.Schemes("https")

...or header values:

	r.Headers("X-Requested-With", "XMLHttpRequest")

...or query values:

	r.Queries("key", "value")

...or to use a custom matcher function:

	r.MatcherFunc(func(r *http.Request, rm *RouteMatch) bool {
		return r.ProtoMajor == 0
	})

...and finally, it is possible to combine several matchers in a single route:

	r.HandleFunc("/products", ProductsHandler).
	  Host("www.example.com").
	  Methods("GET").
	  Schemes("http")

Setting the same matching conditions again and again can be boring, so we have
a way to group several routes that share the same requirements.
We call it "subrouting".

For example, let's say we have several URLs that should only match when the
host is "www.example.com". Create a route for that host and get a "subrouter"
from it:

	r := mux.NewRouter()
	s := r.Host("www.example.com").Subrouter()

Then register routes in the subrouter:

	s.HandleFunc("/products/", ProductsHandler)
	s.HandleFunc("/products/{key}", ProductHandler)
	s.HandleFunc("/articles/{category}/{id:[0-9]+}"), ArticleHandler)

The three URL paths we registered above will only be tested if the domain is
"www.example.com", because the subrouter is tested first. This is not
only convenient, but also optimizes request matching. You can create
subrouters combining any attribute matchers accepted by a route.

Subrouters can be used to create domain or path "namespaces": you define
subrouters in a central place and then parts of the app can register its
paths relatively to a given subrouter.

There's one more thing about subroutes. When a subrouter has a path prefix,
the inner routes use it as base for their paths:

	r := mux.NewRouter()
	s := r.PathPrefix("/products").Subrouter()
	// "/products/"
	s.HandleFunc("/", ProductsHandler)
	// "/products/{key}/"
	s.HandleFunc("/{key}/", ProductHandler)
	// "/products/{key}/details"
	s.HandleFunc("/{key}/details", ProductDetailsHandler)

Note that the path provided to PathPrefix() represents a "wildcard": calling
PathPrefix("/static/").Handler(...) means that the handler will be passed any
request that matches "/static/*". This makes it easy to serve static files with mux:

	func main() {
		var dir string

		flag.StringVar(&dir, "dir", ".", "the directory to serve files from. Defaults to the current dir")
		flag.Parse()
		r := mux.NewRouter()

		// This will serve files under http://localhost:8000/static/<filename>
		r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(dir))))

		srv := &http.Server{
			Handler:      r,
			Addr:         "127.0.0.1:8000",
			// Good practice: enforce timeouts for servers you create!
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}

		log.Fatal(srv.ListenAndServe())
	}

Now let's see how to build registered URLs.

Routes can be named. All routes that define a name can have their URLs built,
or "reversed". We define a name calling Name() on a route. For example:

	r := mux.NewRouter()
	r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler).
	  Name("article")

To build a URL, get the route and call the URL() method, passing a sequence of
key/value pairs for the route variables. For the previous route, we would do:

	url, err := r.Get("article").URL("category", "technology", "id", "42")

...and the result will be a url.URL with the following path:

	"/articles/technology/42"

This also works for host and query value variables:

	r := mux.NewRouter()
	r.Host("{subdomain}.domain.com").
	  Path("/articles/{category}/{id:[0-9]+}").
	  Queries("filter", "{filter}").
	  HandlerFunc(ArticleHandler).
	  Name("article")

	// url.String() will be "http://news.domain.com/articles/technology/42?filter=gorilla"
	url, err := r.Get("article").URL("subdomain", "news",
	                                 "category", "technology",
	                                 "id", "42",
	                                 "filter", "gorilla")

All variables defined in the route are required, and their values must
conform to the corresponding patterns. These requirements guarantee that a
generated URL will always match a registered route -- the only exception is
for explicitly defined "build-only" routes which never match.

Regex support also exists for matching Headers within a route. For example, we could do:

	r.HeadersRegexp("Content-Type", "application/(text|json)")

...and the route will match both requests with a Content-Type of `application/json` as well as
`application/text`

There's also a way to build only the URL host or path for a route:
use the methods URLHost() or URLPath() instead. For the previous route,
we would do:

	// "http://news.domain.com/"
	host, err := r.Get("article").URLHost("subdomain", "news")

	// "/articles/technology/42"
	path, err := r.Get("article").URLPath("category", "technology", "id", "42")

And if you use subrouters, host and path defined separately can be built
as well:

	r := mux.NewRouter()
	s := r.Host("{subdomain}.domain.com").Subrouter()
	s.Path("/articles/{category}/{id:[0-9]+}").
	  HandlerFunc(ArticleHandler).
	  Name("article")

	// "http://news.domain.com/articles/technology/42"
	url, err := r.Get("article").URL("subdomain", "news",
	                                 "category", "technology",
	                                 "id", "42")

Mux supports the addition of middlewares to a Router, which are executed in the order they are added if a match is found, including its subrouters. Middlewares are (typically) small pieces of code which take one request, do something with it, and pass it down to another middleware or the final handler. Some common use cases for middleware are request logging, header manipulation, or ResponseWriter hijacking.

	type MiddlewareFunc func(http.Handler) http.Handler

Typically, the returned handler is a closure which does something with the http.ResponseWriter and http.Request passed to it, and then calls the handler passed as parameter to the MiddlewareFunc (closures can access variables from the context where they are created).

A very basic middleware which logs the URI of the request being handled could be written as:

	func simpleMw(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Do stuff here
			log.Println(r.RequestURI)
			// Call the next handler, which can be another middleware in the chain, or the final handler.
			next.ServeHTTP(w, r)
		})
	}

Middlewares can be added to a router using `Router.Use()`:

	r := mux.NewRouter()
	r.HandleFunc("/", handler)
	r.Use(simpleMw)

A more complex authentication middleware, which maps session token to users, could be written as:

	// Define our struct
	type authenticationMiddleware struct {
		tokenUsers map[string]string
	}

	// Initialize it somewhere
	func (amw *authenticationMiddleware) Populate() {
		amw.tokenUsers["00000000"] = "user0"
		amw.tokenUsers["aaaaaaaa"] = "userA"
		amw.tokenUsers["05f717e5"] = "randomUser"
		amw.tokenUsers["deadbeef"] = "user0"
	}

	// Middleware function, which will be called for each request
	func (amw *authenticationMiddleware) Middleware(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-Session-Token")

			if user, found := amw.tokenUsers[token]; found {
				// We found the token in our map
				log.Printf("Authenticated user %s\n", user)
				next.ServeHTTP(w, r)
			} else {
				http.Error(w, "Forbidden", http.StatusForbidden)
			}
		})
	}

	r := mux.NewRouter()
	r.HandleFunc("/", handler)

	amw := authenticationMiddleware{tokenUsers: make(map[string]string)}
	amw.Populate()

	r.Use(amw.Middleware)

Note: The handler chain will be stopped if your middleware doesn't call `next.ServeHTTP()` with the corresponding parameters. This can be used to abort a request if the middleware writer wants to.
*/
package mux
"#,
    ),
    (
        "middleware.go",
        r#"package mux

import (
	"net/http"
	"strings"
)

// MiddlewareFunc is a function which receives an http.Handler and returns another http.Handler.
// Typically, the returned handler is a closure which does something with the http.ResponseWriter and http.Request passed
// to it, and then calls the handler passed as parameter to the MiddlewareFunc.
type MiddlewareFunc func(http.Handler) http.Handler

// middleware interface is anything which implements a MiddlewareFunc named Middleware.
type middleware interface {
	Middleware(handler http.Handler) http.Handler
}

// Middleware allows MiddlewareFunc to implement the middleware interface.
func (mw MiddlewareFunc) Middleware(handler http.Handler) http.Handler {
	return mw(handler)
}

// Use appends a MiddlewareFunc to the chain. Middleware can be used to intercept or otherwise modify requests and/or responses, and are executed in the order that they are applied to the Router.
func (r *Router) Use(mwf ...MiddlewareFunc) {
	for _, fn := range mwf {
		r.middlewares = append(r.middlewares, fn)
	}
}

// useInterface appends a middleware to the chain. Middleware can be used to intercept or otherwise modify requests and/or responses, and are executed in the order that they are applied to the Router.
func (r *Router) useInterface(mw middleware) {
	r.middlewares = append(r.middlewares, mw)
}

// RouteMiddleware -------------------------------------------------------------

// Use appends a MiddlewareFunc to the chain. Middleware can be used to intercept or otherwise modify requests and/or responses, and are executed in the order that they are applied to the Route. Route middleware are executed after the Router middleware but before the Route handler.
func (r *Route) Use(mwf ...MiddlewareFunc) *Route {
	for _, fn := range mwf {
		r.middlewares = append(r.middlewares, fn)
	}

	return r
}

// useInterface appends a MiddlewareFunc to the chain. Middleware can be used to intercept or otherwise modify requests and/or responses, and are executed in the order that they are applied to the Route. Route middleware are executed after the Router middleware but before the Route handler.
func (r *Route) useInterface(mw middleware) {
	r.middlewares = append(r.middlewares, mw)
}

// CORSMethodMiddleware automatically sets the Access-Control-Allow-Methods response header
// on requests for routes that have an OPTIONS method matcher to all the method matchers on
// the route. Routes that do not explicitly handle OPTIONS requests will not be processed
// by the middleware. See examples for usage.
func CORSMethodMiddleware(r *Router) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			allMethods, err := getAllMethodsForRoute(r, req)
			if err == nil {
				for _, v := range allMethods {
					if v == http.MethodOptions {
						w.Header().Set("Access-Control-Allow-Methods", strings.Join(allMethods, ","))
					}
				}
			}

			next.ServeHTTP(w, req)
		})
	}
}

// getAllMethodsForRoute returns all the methods from method matchers matching a given
// request.
func getAllMethodsForRoute(r *Router, req *http.Request) ([]string, error) {
	var allMethods []string

	for _, route := range r.routes {
		var match RouteMatch
		if route.Match(req, &match) || match.MatchErr == ErrMethodMismatch {
			methods, err := route.GetMethods()
			if err != nil {
				return nil, err
			}

			allMethods = append(allMethods, methods...)
		}
	}

	return allMethods, nil
}
"#,
    ),
    (
        "mux.go",
        r#"// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mux

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
)

var (
	// ErrMethodMismatch is returned when the method in the request does not match
	// the method defined against the route.
	ErrMethodMismatch = errors.New("method is not allowed")
	// ErrNotFound is returned when no route match is found.
	ErrNotFound = errors.New("no matching route was found")
	// RegexpCompileFunc aliases regexp.Compile and enables overriding it.
	// Do not run this function from `init()` in importable packages.
	// Changing this value is not safe for concurrent use.
	RegexpCompileFunc = regexp.Compile
	// ErrMetadataKeyNotFound is returned when the specified metadata key is not present in the map
	ErrMetadataKeyNotFound = errors.New("key not found in metadata")
)

// NewRouter returns a new router instance.
func NewRouter() *Router {
	return &Router{namedRoutes: make(map[string]*Route)}
}

// Router registers routes to be matched and dispatches a handler.
//
// It implements the http.Handler interface, so it can be registered to serve
// requests:
//
//	var router = mux.NewRouter()
//
//	func main() {
//	    http.Handle("/", router)
//	}
//
// Or, for Google App Engine, register it in a init() function:
//
//	func init() {
//	    http.Handle("/", router)
//	}
//
// This will send all incoming requests to the router.
type Router struct {
	// Configurable Handler to be used when no route matches.
	// This can be used to render your own 404 Not Found errors.
	NotFoundHandler http.Handler

	// Configurable Handler to be used when the request method does not match the route.
	// This can be used to render your own 405 Method Not Allowed errors.
	MethodNotAllowedHandler http.Handler

	// Routes to be matched, in order.
	routes []*Route

	// Routes by name for URL building.
	namedRoutes map[string]*Route

	// If true, do not clear the request context after handling the request.
	//
	// Deprecated: No effect, since the context is stored on the request itself.
	KeepContext bool

	// Slice of middlewares to be called after a match is found
	middlewares []middleware

	// configuration shared with `Route`
	routeConf
}

// common route configuration shared between `Router` and `Route`
type routeConf struct {
	// If true, "/path/foo%2Fbar/to" will match the path "/path/{var}/to"
	useEncodedPath bool

	// If true, when the path pattern is "/path/", accessing "/path" will
	// redirect to the former and vice versa.
	strictSlash bool

	// If true, when the path pattern is "/path//to", accessing "/path//to"
	// will not redirect
	skipClean bool

	// If true, the http.Request context will not contain the Route.
	omitRouteFromContext bool

	// if true, the the http.Request context will not contain the router
	omitRouterFromContext bool

	// Manager for the variables from host and path.
	regexp routeRegexpGroup

	// List of matchers.
	matchers []matcher

	// The scheme used when building URLs.
	buildScheme string

	buildVarsFunc BuildVarsFunc
}

// returns an effective deep copy of `routeConf`
func copyRouteConf(r routeConf) routeConf {
	c := r

	if r.regexp.path != nil {
		c.regexp.path = copyRouteRegexp(r.regexp.path)
	}

	if r.regexp.host != nil {
		c.regexp.host = copyRouteRegexp(r.regexp.host)
	}

	c.regexp.queries = make([]*routeRegexp, 0, len(r.regexp.queries))
	for _, q := range r.regexp.queries {
		c.regexp.queries = append(c.regexp.queries, copyRouteRegexp(q))
	}

	c.matchers = make([]matcher, len(r.matchers))
	copy(c.matchers, r.matchers)

	return c
}

func copyRouteRegexp(r *routeRegexp) *routeRegexp {
	c := *r
	return &c
}

// Match attempts to match the given request against the router's registered routes.
//
// If the request matches a route of this router or one of its subrouters the Route,
// Handler, and Vars fields of the the match argument are filled and this function
// returns true.
//
// If the request does not match any of this router's or its subrouters' routes
// then this function returns false. If available, a reason for the match failure
// will be filled in the match argument's MatchErr field. If the match failure type
// (eg: not found) has a registered handler, the handler is assigned to the Handler
// field of the match argument.
func (r *Router) Match(req *http.Request, match *RouteMatch) bool {
	for _, route := range r.routes {
		if route.Match(req, match) {
			// Build middleware chain if no error was found
			if match.MatchErr == nil {
				for i := len(r.middlewares) - 1; i >= 0; i-- {
					match.Handler = r.middlewares[i].Middleware(match.Handler)
				}
			}
			return true
		}
	}

	if match.MatchErr == ErrMethodMismatch {
		if r.MethodNotAllowedHandler != nil {
			match.Handler = r.MethodNotAllowedHandler
			return true
		}

		return false
	}

	// Closest match for a router (includes sub-routers)
	if r.NotFoundHandler != nil {
		match.Handler = r.NotFoundHandler
		match.MatchErr = ErrNotFound
		return true
	}

	match.MatchErr = ErrNotFound
	return false
}

// ServeHTTP dispatches the handler registered in the matched route.
//
// When there is a match, the route variables can be retrieved calling
// mux.Vars(request).
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !r.skipClean {
		path := req.URL.Path
		if r.useEncodedPath {
			path = req.URL.EscapedPath()
		}
		// Clean path to canonical form and redirect.
		if p := cleanPath(path); p != path {
			w.Header().Set("Location", replaceURLPath(req.URL, p))
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
	}
	var match RouteMatch
	var handler http.Handler
	if r.Match(req, &match) {
		handler = match.Handler
		if handler != nil {
			// Populate context for custom handlers
			if r.omitRouteFromContext {
				// Only populate the match vars (if any) into the context.
				req = requestWithVars(req, match.Vars)
			} else {
				req = requestWithRouteAndVars(req, match.Route, match.Vars)
			}

			if !r.omitRouterFromContext {
				req = requestWithRouter(req, r)
			}
		}
	}

	if handler == nil && match.MatchErr == ErrMethodMismatch {
		handler = methodNotAllowedHandler()
	}

	if handler == nil {
		handler = http.NotFoundHandler()
	}

	handler.ServeHTTP(w, req)
}

// Get returns a route registered with the given name.
func (r *Router) Get(name string) *Route {
	return r.namedRoutes[name]
}

// GetRoute returns a route registered with the given name. This method
// was renamed to Get() and remains here for backwards compatibility.
func (r *Router) GetRoute(name string) *Route {
	return r.namedRoutes[name]
}

// StrictSlash defines the trailing slash behavior for new routes. The initial
// value is false.
//
// When true, if the route path is "/path/", accessing "/path" will perform a redirect
// to the former and vice versa. In other words, your application will always
// see the path as specified in the route.
//
// When false, if the route path is "/path", accessing "/path/" will not match
// this route and vice versa.
//
// The redirect is a HTTP 301 (Moved Permanently). Note that when this is set for
// routes with a non-idempotent method (e.g. POST, PUT), the subsequent redirected
// request will be made as a GET by most clients. Use middleware or client settings
// to modify this behaviour as needed.
//
// Special case: when a route sets a path prefix using the PathPrefix() method,
// strict slash is ignored for that route because the redirect behavior can't
// be determined from a prefix alone. However, any subrouters created from that
// route inherit the original StrictSlash setting.
func (r *Router) StrictSlash(value bool) *Router {
	r.strictSlash = value
	return r
}

// SkipClean defines the path cleaning behaviour for new routes. The initial
// value is false. Users should be careful about which routes are not cleaned
//
// When true, if the route path is "/path//to", it will remain with the double
// slash. This is helpful if you have a route like: /fetch/http://xkcd.com/534/
//
// When false, the path will be cleaned, so /fetch/http://xkcd.com/534/ will
// become /fetch/http/xkcd.com/534
func (r *Router) SkipClean(value bool) *Router {
	r.skipClean = value
	return r
}

// OmitRouteFromContext defines the behavior of omitting the Route from the
//
//	http.Request context.
//
// CurrentRoute will yield nil with this option.
func (r *Router) OmitRouteFromContext(value bool) *Router {
	r.omitRouteFromContext = value
	return r
}

// OmitRouterFromContext defines the behavior of omitting the Router from the
// http.Request context.
//
// RouterFromRequest will yield nil with this option.
func (r *Router) OmitRouterFromContext(value bool) *Router {
	r.omitRouterFromContext = value
	return r
}

// UseEncodedPath tells the router to match the encoded original path
// to the routes.
// For eg. "/path/foo%2Fbar/to" will match the path "/path/{var}/to".
//
// If not called, the router will match the unencoded path to the routes.
// For eg. "/path/foo%2Fbar/to" will match the path "/path/foo/bar/to"
func (r *Router) UseEncodedPath() *Router {
	r.useEncodedPath = true
	return r
}

// ----------------------------------------------------------------------------
// Route factories
// ----------------------------------------------------------------------------

// NewRoute registers an empty route.
func (r *Router) NewRoute() *Route {
	// initialize a route with a copy of the parent router's configuration
	route := &Route{routeConf: copyRouteConf(r.routeConf), namedRoutes: r.namedRoutes}
	r.routes = append(r.routes, route)
	return route
}

// Name registers a new route with a name.
// See Route.Name().
func (r *Router) Name(name string) *Route {
	return r.NewRoute().Name(name)
}

// Handle registers a new route with a matcher for the URL path.
// See Route.Path() and Route.Handler().
func (r *Router) Handle(path string, handler http.Handler) *Route {
	return r.NewRoute().Path(path).Handler(handler)
}

// HandleFunc registers a new route with a matcher for the URL path.
// See Route.Path() and Route.HandlerFunc().
func (r *Router) HandleFunc(path string, f func(http.ResponseWriter,
	*http.Request)) *Route {
	return r.NewRoute().Path(path).HandlerFunc(f)
}

// Headers registers a new route with a matcher for request header values.
// See Route.Headers().
func (r *Router) Headers(pairs ...string) *Route {
	return r.NewRoute().Headers(pairs...)
}

// Host registers a new route with a matcher for the URL host.
// See Route.Host().
func (r *Router) Host(tpl string) *Route {
	return r.NewRoute().Host(tpl)
}

// MatcherFunc registers a new route with a custom matcher function.
// See Route.MatcherFunc().
func (r *Router) MatcherFunc(f MatcherFunc) *Route {
	return r.NewRoute().MatcherFunc(f)
}

// Methods registers a new route with a matcher for HTTP methods.
// See Route.Methods().
func (r *Router) Methods(methods ...string) *Route {
	return r.NewRoute().Methods(methods...)
}

// Path registers a new route with a matcher for the URL path.
// See Route.Path().
func (r *Router) Path(tpl string) *Route {
	return r.NewRoute().Path(tpl)
}

// PathPrefix registers a new route with a matcher for the URL path prefix.
// See Route.PathPrefix().
func (r *Router) PathPrefix(tpl string) *Route {
	return r.NewRoute().PathPrefix(tpl)
}

// Queries registers a new route with a matcher for URL query values.
// See Route.Queries().
func (r *Router) Queries(pairs ...string) *Route {
	return r.NewRoute().Queries(pairs...)
}

// Schemes registers a new route with a matcher for URL schemes.
// See Route.Schemes().
func (r *Router) Schemes(schemes ...string) *Route {
	return r.NewRoute().Schemes(schemes...)
}

// BuildVarsFunc registers a new route with a custom function for modifying
// route variables before building a URL.
func (r *Router) BuildVarsFunc(f BuildVarsFunc) *Route {
	return r.NewRoute().BuildVarsFunc(f)
}

// Walk walks the router and all its sub-routers, calling walkFn for each route
// in the tree. The routes are walked in the order they were added. Sub-routers
// are explored depth-first.
func (r *Router) Walk(walkFn WalkFunc) error {
	return r.walk(walkFn, []*Route{})
}

// SkipRouter is used as a return value from WalkFuncs to indicate that the
// router that walk is about to descend down to should be skipped.
var SkipRouter = errors.New("skip this router")

// WalkFunc is the type of the function called for each route visited by Walk.
// At every invocation, it is given the current route, and the current router,
// and a list of ancestor routes that lead to the current route.
type WalkFunc func(route *Route, router *Router, ancestors []*Route) error

func (r *Router) walk(walkFn WalkFunc, ancestors []*Route) error {
	for _, t := range r.routes {
		err := walkFn(t, r, ancestors)
		if err == SkipRouter {
			continue
		}
		if err != nil {
			return err
		}
		for _, sr := range t.matchers {
			if h, ok := sr.(*Router); ok {
				ancestors = append(ancestors, t)
				err := h.walk(walkFn, ancestors)
				if err != nil {
					return err
				}
				ancestors = ancestors[:len(ancestors)-1]
			}
		}
		if h, ok := t.handler.(*Router); ok {
			ancestors = append(ancestors, t)
			err := h.walk(walkFn, ancestors)
			if err != nil {
				return err
			}
			ancestors = ancestors[:len(ancestors)-1]
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// Context
// ----------------------------------------------------------------------------

// RouteMatch stores information about a matched route.
type RouteMatch struct {
	Route   *Route
	Handler http.Handler
	Vars    map[string]string

	// MatchErr is set to appropriate matching error
	// It is set to ErrMethodMismatch if there is a mismatch in
	// the request method and route method
	MatchErr error
}

type contextKey int

const (
	varsKey contextKey = iota
	routeKey
	routerKey
)

// Vars returns the route variables for the current request, if any.
func Vars(r *http.Request) map[string]string {
	if rv := r.Context().Value(varsKey); rv != nil {
		return rv.(map[string]string)
	}
	return nil
}

// CurrentRoute returns the matched route for the current request, if any.
// This only works when called inside the handler of the matched route
// because the matched route is stored in the request context which is cleared
// after the handler returns.
func CurrentRoute(r *http.Request) *Route {
	if rv := r.Context().Value(routeKey); rv != nil {
		return rv.(*Route)
	}
	return nil
}

func CurrentRouter(r *http.Request) *Router {
	if rv := r.Context().Value(routerKey); rv != nil {
		return rv.(*Router)
	}
	return nil
}

// requestWithVars adds the matched vars to the request ctx.
// It shortcuts the operation when the vars are empty.
func requestWithVars(r *http.Request, vars map[string]string) *http.Request {
	if len(vars) == 0 {
		return r
	}
	ctx := context.WithValue(r.Context(), varsKey, vars)
	return r.WithContext(ctx)
}

// requestWithRouteAndVars adds the matched route and vars to the request ctx.
// It saves extra allocations in cloning the request once and skipping the
//
//	population of empty vars, which in turn mux.Vars can handle gracefully.
func requestWithRouteAndVars(r *http.Request, route *Route, vars map[string]string) *http.Request {
	ctx := context.WithValue(r.Context(), routeKey, route)
	if len(vars) > 0 {
		ctx = context.WithValue(ctx, varsKey, vars)
	}
	return r.WithContext(ctx)
}

func requestWithRouter(r *http.Request, router *Router) *http.Request {
	ctx := context.WithValue(r.Context(), routerKey, router)
	return r.WithContext(ctx)
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// cleanPath returns the canonical path for p, eliminating . and .. elements.
// Borrowed from the net/http package.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	// path.Clean removes trailing slash except for root;
	// put the trailing slash back if necessary.
	if p[len(p)-1] == '/' && np != "/" {
		np += "/"
	}

	return np
}

// replaceURLPath prints an url.URL with a different path.
func replaceURLPath(u *url.URL, p string) string {
	// Operate on a copy of the request url.
	u2 := *u
	u2.Path = p
	return u2.String()
}

// uniqueVars returns an error if two slices contain duplicated strings.
func uniqueVars(s1, s2 []string) error {
	for _, v1 := range s1 {
		for _, v2 := range s2 {
			if v1 == v2 {
				return fmt.Errorf("mux: duplicated route variable %q", v2)
			}
		}
	}
	return nil
}

// checkPairs returns the count of strings passed in, and an error if
// the count is not an even number.
func checkPairs(pairs ...string) (int, error) {
	length := len(pairs)
	if length%2 != 0 {
		return length, fmt.Errorf(
			"mux: number of parameters must be multiple of 2, got %v", pairs)
	}
	return length, nil
}

// mapFromPairsToString converts variadic string parameters to a
// string to string map.
func mapFromPairsToString(pairs ...string) (map[string]string, error) {
	length, err := checkPairs(pairs...)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, length/2)
	for i := 0; i < length; i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return m, nil
}

// mapFromPairsToRegex converts variadic string parameters to a
// string to regex map.
func mapFromPairsToRegex(pairs ...string) (map[string]*regexp.Regexp, error) {
	length, err := checkPairs(pairs...)
	if err != nil {
		return nil, err
	}
	m := make(map[string]*regexp.Regexp, length/2)
	for i := 0; i < length; i += 2 {
		regex, err := RegexpCompileFunc(pairs[i+1])
		if err != nil {
			return nil, err
		}
		m[pairs[i]] = regex
	}
	return m, nil
}

// matchInArray returns true if the given string value is in the array.
func matchInArray(arr []string, value string) bool {
	for _, v := range arr {
		if v == value {
			return true
		}
	}
	return false
}

// matchMapWithString returns true if the given key/value pairs exist in a given map.
func matchMapWithString(toCheck map[string]string, toMatch map[string][]string, canonicalKey bool) bool {
	for k, v := range toCheck {
		// Check if key exists.
		if canonicalKey {
			k = http.CanonicalHeaderKey(k)
		}
		if values := toMatch[k]; values == nil {
			return false
		} else if v != "" {
			// If value was defined as an empty string we only check that the
			// key exists. Otherwise we also check for equality.
			valueExists := false
			for _, value := range values {
				if v == value {
					valueExists = true
					break
				}
			}
			if !valueExists {
				return false
			}
		}
	}
	return true
}

// matchMapWithRegex returns true if the given key/value pairs exist in a given map compiled against
// the given regex
func matchMapWithRegex(toCheck map[string]*regexp.Regexp, toMatch map[string][]string, canonicalKey bool) bool {
	for k, v := range toCheck {
		// Check if key exists.
		if canonicalKey {
			k = http.CanonicalHeaderKey(k)
		}
		if values := toMatch[k]; values == nil {
			return false
		} else if v != nil {
			// If value was defined as an empty string we only check that the
			// key exists. Otherwise we also check for equality.
			valueExists := false
			for _, value := range values {
				if v.MatchString(value) {
					valueExists = true
					break
				}
			}
			if !valueExists {
				return false
			}
		}
	}
	return true
}

// methodNotAllowed replies to the request with an HTTP status code 405.
func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// methodNotAllowedHandler returns a simple request handler
// that replies to each request with a status code 405.
func methodNotAllowedHandler() http.Handler { return http.HandlerFunc(methodNotAllowed) }
"#,
    ),
    (
        "regexp.go",
        r#"// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mux

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type routeRegexpOptions struct {
	strictSlash    bool
	useEncodedPath bool
}

type regexpType int

const (
	regexpTypePath regexpType = iota
	regexpTypeHost
	regexpTypePrefix
	regexpTypeQuery
)

// newRouteRegexp parses a route template and returns a routeRegexp,
// used to match a host, a path or a query string.
//
// It will extract named variables, assemble a regexp to be matched, create
// a "reverse" template to build URLs and compile regexps to validate variable
// values used in URL building.
//
// Previously we accepted only Python-like identifiers for variable
// names ([a-zA-Z_][a-zA-Z0-9_]*), but currently the only restriction is that
// name and pattern can't be empty, and names can't contain a colon.
func newRouteRegexp(tpl string, typ regexpType, options routeRegexpOptions) (*routeRegexp, error) {
	// Check if it is well-formed.
	idxs, errBraces := braceIndices(tpl)
	if errBraces != nil {
		return nil, errBraces
	}
	// Backup the original.
	template := tpl
	// Now let's parse it.
	defaultPattern := "[^/]+"
	if typ == regexpTypeQuery {
		defaultPattern = ".*"
	} else if typ == regexpTypeHost {
		defaultPattern = "[^.]+"
	}
	// Only match strict slash if not matching
	if typ != regexpTypePath {
		options.strictSlash = false
	}
	// Set a flag for strictSlash.
	endSlash := false
	if options.strictSlash && strings.HasSuffix(tpl, "/") {
		tpl = tpl[:len(tpl)-1]
		endSlash = true
	}
	varsN := make([]string, len(idxs)/2)
	varsR := make([]*regexp.Regexp, len(idxs)/2)

	var pattern, reverse strings.Builder
	pattern.WriteByte('^')

	var end, colonIdx, groupIdx int
	var err error
	var patt, param, name string
	for i := 0; i < len(idxs); i += 2 {
		// Set all values we are interested in.
		groupIdx = i / 2

		raw := tpl[end:idxs[i]]
		end = idxs[i+1]
		tag := tpl[idxs[i]:end]

		// trim braces from tag
		param = tag[1 : len(tag)-1]

		colonIdx = strings.Index(param, ":")
		if colonIdx == -1 {
			name = param
			patt = defaultPattern
		} else {
			name = param[0:colonIdx]
			patt = param[colonIdx+1:]
		}

		// Name or pattern can't be empty.
		if name == "" || patt == "" {
			return nil, fmt.Errorf("mux: missing name or pattern in %q", tag)
		}
		// Build the regexp pattern.
		groupName := varGroupName(groupIdx)

		pattern.WriteString(regexp.QuoteMeta(raw) + "(?P<" + groupName + ">" + patt + ")")

		// Build the reverse template.
		reverse.WriteString(raw + "%s")

		// Append variable name and compiled pattern.
		varsN[groupIdx] = name
		varsR[groupIdx], err = RegexpCompileFunc("^" + patt + "$")
		if err != nil {
			return nil, fmt.Errorf("mux: error compiling regex for %q: %w", tag, err)
		}
	}
	// Add the remaining.
	raw := tpl[end:]
	pattern.WriteString(regexp.QuoteMeta(raw))
	if options.strictSlash {
		pattern.WriteString("[/]?")
	}
	if typ == regexpTypeQuery {
		// Add the default pattern if the query value is empty
		if queryVal := strings.SplitN(template, "=", 2)[1]; queryVal == "" {
			pattern.WriteString(defaultPattern)
		}
	}
	if typ != regexpTypePrefix {
		pattern.WriteByte('$')
	}

	// Compile full regexp.
	patternStr := pattern.String()
	reg, errCompile := RegexpCompileFunc(patternStr)
	if errCompile != nil {
		return nil, errCompile
	}

	// Check for capturing groups which used to work in older versions
	if reg.NumSubexp() != len(idxs)/2 {
		panic(fmt.Sprintf("route %s contains capture groups in its regexp. ", template) +
			"Only non-capturing groups are accepted: e.g. (?:pattern) instead of (pattern)")
	}

	var wildcardHostPort bool
	if typ == regexpTypeHost {
		if !strings.Contains(patternStr, ":") {
			wildcardHostPort = true
		}
	}
	reverse.WriteString(raw)
	if endSlash {
		reverse.WriteByte('/')
	}

	// Done!
	return &routeRegexp{
		template:         template,
		regexpType:       typ,
		options:          options,
		regexp:           reg,
		reverse:          reverse.String(),
		varsN:            varsN,
		varsR:            varsR,
		wildcardHostPort: wildcardHostPort,
	}, nil
}

// routeRegexp stores a regexp to match a host or path and information to
// collect and validate route variables.
type routeRegexp struct {
	// The unmodified template.
	template string
	// The type of match
	regexpType regexpType
	// Options for matching
	options routeRegexpOptions
	// Expanded regexp.
	regexp *regexp.Regexp
	// Reverse template.
	reverse string
	// Variable names.
	varsN []string
	// Variable regexps (validators).
	varsR []*regexp.Regexp
	// Wildcard host-port (no strict port match in hostname)
	wildcardHostPort bool
}

// Match matches the regexp against the URL host or path.
func (r *routeRegexp) Match(req *http.Request, match *RouteMatch) bool {
	if r.regexpType == regexpTypeHost {
		host := getHost(req)
		if r.wildcardHostPort {
			// Don't be strict on the port match
			if i := strings.Index(host, ":"); i != -1 {
				host = host[:i]
			}
		}
		return r.regexp.MatchString(host)
	}

	if r.regexpType == regexpTypeQuery {
		return r.matchQueryString(req)
	}
	path := req.URL.Path
	if r.options.useEncodedPath {
		path = req.URL.EscapedPath()
	}
	return r.regexp.MatchString(path)
}

// url builds a URL part using the given values.
func (r *routeRegexp) url(values map[string]string) (string, error) {
	urlValues := make([]interface{}, len(r.varsN))
	for k, v := range r.varsN {
		value, ok := values[v]
		if !ok {
			return "", fmt.Errorf("mux: missing route variable %q", v)
		}
		if r.regexpType == regexpTypeQuery {
			value = url.QueryEscape(value)
		}
		urlValues[k] = value
	}
	rv := fmt.Sprintf(r.reverse, urlValues...)
	if !r.regexp.MatchString(rv) {
		// The URL is checked against the full regexp, instead of checking
		// individual variables. This is faster but to provide a good error
		// message, we check individual regexps if the URL doesn't match.
		for k, v := range r.varsN {
			if !r.varsR[k].MatchString(values[v]) {
				return "", fmt.Errorf(
					"mux: variable %q doesn't match, expected %q", values[v],
					r.varsR[k].String())
			}
		}
	}
	return rv, nil
}

// getURLQuery returns a single query parameter from a request URL.
// For a URL with foo=bar&baz=ding, we return only the relevant key
// value pair for the routeRegexp.
func (r *routeRegexp) getURLQuery(req *http.Request) string {
	if r.regexpType != regexpTypeQuery {
		return ""
	}
	templateKey := strings.SplitN(r.template, "=", 2)[0]
	val, ok := findFirstQueryKey(req.URL.RawQuery, templateKey)
	if ok {
		return templateKey + "=" + val
	}
	return ""
}

// findFirstQueryKey returns the same result as (*url.URL).Query()[key][0].
// If key was not found, empty string and false is returned.
func findFirstQueryKey(rawQuery, key string) (value string, ok bool) {
	query := []byte(rawQuery)
	for len(query) > 0 {
		foundKey := query
		if i := bytes.IndexAny(foundKey, "&;"); i >= 0 {
			foundKey, query = foundKey[:i], foundKey[i+1:]
		} else {
			query = query[:0]
		}
		if len(foundKey) == 0 {
			continue
		}
		var value []byte
		if i := bytes.IndexByte(foundKey, '='); i >= 0 {
			foundKey, value = foundKey[:i], foundKey[i+1:]
		}
		if len(foundKey) < len(key) {
			// Cannot possibly be key.
			continue
		}
		keyString, err := url.QueryUnescape(string(foundKey))
		if err != nil {
			continue
		}
		if keyString != key {
			continue
		}
		valueString, err := url.QueryUnescape(string(value))
		if err != nil {
			continue
		}
		return valueString, true
	}
	return "", false
}

func (r *routeRegexp) matchQueryString(req *http.Request) bool {
	return r.regexp.MatchString(r.getURLQuery(req))
}

// braceIndices returns the first level curly brace indices from a string.
// It returns an error in case of unbalanced braces.
func braceIndices(s string) ([]int, error) {
	var level, idx int
	var idxs []int
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			if level++; level == 1 {
				idx = i
			}
		case '}':
			if level--; level == 0 {
				idxs = append(idxs, idx, i+1)
			} else if level < 0 {
				return nil, fmt.Errorf("mux: unbalanced braces in %q", s)
			}
		}
	}
	if level != 0 {
		return nil, fmt.Errorf("mux: unbalanced braces in %q", s)
	}
	return idxs, nil
}

// varGroupName builds a capturing group name for the indexed variable.
func varGroupName(idx int) string {
	return "v" + strconv.Itoa(idx)
}

// ----------------------------------------------------------------------------
// routeRegexpGroup
// ----------------------------------------------------------------------------

// routeRegexpGroup groups the route matchers that carry variables.
type routeRegexpGroup struct {
	host    *routeRegexp
	path    *routeRegexp
	queries []*routeRegexp
}

// setMatch extracts the variables from the URL once a route matches.
func (v routeRegexpGroup) setMatch(req *http.Request, m *RouteMatch, r *Route) {
	// Store host variables.
	if v.host != nil {
		if len(v.host.varsN) > 0 {
			host := getHost(req)
			if v.host.wildcardHostPort {
				// Don't be strict on the port match
				if i := strings.Index(host, ":"); i != -1 {
					host = host[:i]
				}
			}
			matches := v.host.regexp.FindStringSubmatchIndex(host)
			if len(matches) > 0 {
				m.Vars = extractVars(host, matches, v.host.varsN, m.Vars)
			}
		}
	}
	path := req.URL.Path
	if r.useEncodedPath {
		path = req.URL.EscapedPath()
	}
	// Store path variables.
	if v.path != nil {
		if len(v.path.varsN) > 0 {
			matches := v.path.regexp.FindStringSubmatchIndex(path)
			if len(matches) > 0 {
				m.Vars = extractVars(path, matches, v.path.varsN, m.Vars)
			}
		}
		// Check if we should redirect.
		if v.path.options.strictSlash {
			p1 := strings.HasSuffix(path, "/")
			p2 := strings.HasSuffix(v.path.template, "/")
			if p1 != p2 {
				p := req.URL.Path
				if p1 {
					p = p[:len(p)-1]
				} else {
					p += "/"
				}
				u := replaceURLPath(req.URL, p)
				m.Handler = http.RedirectHandler(u, http.StatusMovedPermanently)
			}
		}
	}
	// Store query string variables.
	for _, q := range v.queries {
		if len(q.varsN) > 0 {
			queryURL := q.getURLQuery(req)
			matches := q.regexp.FindStringSubmatchIndex(queryURL)
			if len(matches) > 0 {
				m.Vars = extractVars(queryURL, matches, q.varsN, m.Vars)
			}
		}
	}
}

// getHost tries its best to return the request host.
// According to section 14.23 of RFC 2616 the Host header
// can include the port number if the default value of 80 is not used.
func getHost(r *http.Request) string {
	if r.URL.IsAbs() {
		return r.URL.Host
	}
	return r.Host
}

func extractVars(input string, matches []int, names []string, output map[string]string) map[string]string {
	for i, name := range names {
		if output == nil {
			output = make(map[string]string, len(names))
		}
		output[name] = input[matches[2*i+2]:matches[2*i+3]]
	}
	return output
}
"#,
    ),
    (
        "route.go",
        r#"// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mux

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Route stores information to match a request and build URLs.
type Route struct {
	// Request handler for the route.
	handler http.Handler
	// If true, this route never matches: it is only used to build URLs.
	buildOnly bool
	// The name used to build URLs.
	name string
	// Error resulted from building a route.
	err error

	// The meta data associated with this route
	metadata map[any]any

	// "global" reference to all named routes
	namedRoutes map[string]*Route

	// route specific middleware
	middlewares []middleware

	// config possibly passed in from `Router`
	routeConf
}

// SkipClean reports whether path cleaning is enabled for this route via
// Router.SkipClean.
func (r *Route) SkipClean() bool {
	return r.skipClean
}

// Match matches the route against the request.
func (r *Route) Match(req *http.Request, match *RouteMatch) bool {
	if r.buildOnly || r.err != nil {
		return false
	}

	var matchErr error

	// Match everything.
	for _, m := range r.matchers {
		if matched := m.Match(req, match); !matched {
			if _, ok := m.(methodMatcher); ok {
				matchErr = ErrMethodMismatch
				continue
			}

			// Multiple routes may share the same path but use different HTTP methods. For instance:
			// Route 1: POST "/users/{id}".
			// Route 2: GET "/users/{id}", parameters: "id": "[0-9]+".
			//
			// The router must handle these cases correctly. For a GET request to "/users/abc" with "id" as "-2",
			// The router should return a "Not Found" error as no route fully matches this request.
			if rr, ok := m.(*routeRegexp); ok {
				if rr.regexpType == regexpTypeQuery {
					matchErr = ErrNotFound
					break
				}
			}

			// Ignore ErrNotFound errors. These errors arise from match call
			// to Subrouters.
			//
			// This prevents subsequent matching subrouters from failing to
			// run middleware. If not ignored, the middleware would see a
			// non-nil MatchErr and be skipped, even when there was a
			// matching route.
			if match.MatchErr == ErrNotFound {
				match.MatchErr = nil
			}

			matchErr = nil // nolint:ineffassign
			return false
		}
	}

	if matchErr != nil {
		match.MatchErr = matchErr
		return false
	}

	if match.MatchErr != nil && r.handler != nil {
		// We found a route which matches request method, clear MatchErr
		match.MatchErr = nil
		// Then override the mis-matched handler
		match.Handler = r.handler
	}

	// Yay, we have a match. Let's collect some info about it.
	if match.Route == nil {
		match.Route = r
	}
	if match.Handler == nil {
		match.Handler = r.GetHandlerWithMiddlewares()
	}

	// Set variables.
	r.regexp.setMatch(req, match, r)
	return true
}

// ----------------------------------------------------------------------------
// Route attributes
// ----------------------------------------------------------------------------

// GetError returns an error resulted from building the route, if any.
func (r *Route) GetError() error {
	return r.err
}

// BuildOnly sets the route to never match: it is only used to build URLs.
func (r *Route) BuildOnly() *Route {
	r.buildOnly = true
	return r
}

// MetaData -------------------------------------------------------------------

// Metadata is used to set metadata on a route
func (r *Route) Metadata(key any, value any) *Route {
	if r.metadata == nil {
		r.metadata = make(map[any]any)
	}

	r.metadata[key] = value
	return r
}

// GetMetadata returns the metadata map for route
func (r *Route) GetMetadata() map[any]any {
	return r.metadata
}

// MetadataContains returns whether or not the key is present in the metadata map
func (r *Route) MetadataContains(key any) bool {
	_, ok := r.metadata[key]
	return ok
}

// GetMetadataValue returns the value of a specific key in the metadata map. If the key is not present in the map mux.ErrMetadataKeyNotFound is returned
func (r *Route) GetMetadataValue(key any) (any, error) {
	value, ok := r.metadata[key]
	if !ok {
		return nil, ErrMetadataKeyNotFound
	}

	return value, nil
}

// GetMetadataValueOr returns the value of a specific key in the metadata map. If the key is not present in the metadata the fallback value is returned
func (r *Route) GetMetadataValueOr(key any, fallbackValue any) any {
	value, ok := r.metadata[key]
	if !ok {
		return fallbackValue
	}

	return value
}

// Handler --------------------------------------------------------------------

// Handler sets a handler for the route.
func (r *Route) Handler(handler http.Handler) *Route {
	if r.err == nil {
		r.handler = handler
	}
	return r
}

// HandlerFunc sets a handler function for the route.
func (r *Route) HandlerFunc(f func(http.ResponseWriter, *http.Request)) *Route {
	return r.Handler(http.HandlerFunc(f))
}

// GetHandler returns the handler for the route, if any.
func (r *Route) GetHandler() http.Handler {
	return r.handler
}

// GetHandlerWithMiddleware returns the route handler wrapped in the assigned middlewares.
// If no middlewares are specified, just the handler, if any, is returned.
func (r *Route) GetHandlerWithMiddlewares() http.Handler {
	handler := r.handler

	if handler != nil && len(r.middlewares) > 0 {
		for i := len(r.middlewares) - 1; i >= 0; i-- {
			handler = r.middlewares[i].Middleware(handler)
		}
	}

	return handler
}

// Name -----------------------------------------------------------------------

// Name sets the name for the route, used to build URLs.
// It is an error to call Name more than once on a route.
func (r *Route) Name(name string) *Route {
	if r.name != "" {
		r.err = fmt.Errorf("mux: route already has name %q, can't set %q",
			r.name, name)
	}
	if r.err == nil {
		r.name = name
		r.namedRoutes[name] = r
	}
	return r
}

// GetName returns the name for the route, if any.
func (r *Route) GetName() string {
	return r.name
}

// ----------------------------------------------------------------------------
// Matchers
// ----------------------------------------------------------------------------

// matcher types try to match a request.
type matcher interface {
	Match(*http.Request, *RouteMatch) bool
}

// addMatcher adds a matcher to the route.
func (r *Route) addMatcher(m matcher) *Route {
	if r.err == nil {
		r.matchers = append(r.matchers, m)
	}
	return r
}

// addRegexpMatcher adds a host or path matcher and builder to a route.
func (r *Route) addRegexpMatcher(tpl string, typ regexpType) error {
	if r.err != nil {
		return r.err
	}
	if typ == regexpTypePath || typ == regexpTypePrefix {
		if len(tpl) > 0 && tpl[0] != '/' {
			return fmt.Errorf("mux: path must start with a slash, got %q", tpl)
		}
		if r.regexp.path != nil {
			tpl = strings.TrimRight(r.regexp.path.template, "/") + tpl
		}
	}
	rr, err := newRouteRegexp(tpl, typ, routeRegexpOptions{
		strictSlash:    r.strictSlash,
		useEncodedPath: r.useEncodedPath,
	})
	if err != nil {
		return err
	}
	for _, q := range r.regexp.queries {
		if err = uniqueVars(rr.varsN, q.varsN); err != nil {
			return err
		}
	}
	if typ == regexpTypeHost {
		if r.regexp.path != nil {
			if err = uniqueVars(rr.varsN, r.regexp.path.varsN); err != nil {
				return err
			}
		}
		r.regexp.host = rr
	} else {
		if r.regexp.host != nil {
			if err = uniqueVars(rr.varsN, r.regexp.host.varsN); err != nil {
				return err
			}
		}
		if typ == regexpTypeQuery {
			r.regexp.queries = append(r.regexp.queries, rr)
		} else {
			r.regexp.path = rr
		}
	}
	r.addMatcher(rr)
	return nil
}

// Headers --------------------------------------------------------------------

// headerMatcher matches the request against header values.
type headerMatcher map[string]string

func (m headerMatcher) Match(r *http.Request, match *RouteMatch) bool {
	return matchMapWithString(m, r.Header, true)
}

// Headers adds a matcher for request header values.
// It accepts a sequence of key/value pairs to be matched. For example:
//
//	r := mux.NewRouter().NewRoute()
//	r.Headers("Content-Type", "application/json",
//	          "X-Requested-With", "XMLHttpRequest")
//
// The above route will only match if both request header values match.
// If the value is an empty string, it will match any value if the key is set.
func (r *Route) Headers(pairs ...string) *Route {
	if r.err == nil {
		var headers map[string]string
		headers, r.err = mapFromPairsToString(pairs...)
		return r.addMatcher(headerMatcher(headers))
	}
	return r
}

// headerRegexMatcher matches the request against the route given a regex for the header
type headerRegexMatcher map[string]*regexp.Regexp

func (m headerRegexMatcher) Match(r *http.Request, match *RouteMatch) bool {
	return matchMapWithRegex(m, r.Header, true)
}

// HeadersRegexp accepts a sequence of key/value pairs, where the value has regex
// support. For example:
//
//	r := mux.NewRouter().NewRoute()
//	r.HeadersRegexp("Content-Type", "application/(text|json)",
//	          "X-Requested-With", "XMLHttpRequest")
//
// The above route will only match if both the request header matches both regular expressions.
// If the value is an empty string, it will match any value if the key is set.
// Use the start and end of string anchors (^ and $) to match an exact value.
func (r *Route) HeadersRegexp(pairs ...string) *Route {
	if r.err == nil {
		var headers map[string]*regexp.Regexp
		headers, r.err = mapFromPairsToRegex(pairs...)
		return r.addMatcher(headerRegexMatcher(headers))
	}
	return r
}

// Host -----------------------------------------------------------------------

// Host adds a matcher for the URL host.
// It accepts a template with zero or more URL variables enclosed by {}.
// Variables can define an optional regexp pattern to be matched:
//
// - {name} matches anything until the next dot.
//
// - {name:pattern} matches the given regexp pattern.
//
// For example:
//
//	r := mux.NewRouter().NewRoute()
//	r.Host("www.example.com")
//	r.Host("{subdomain}.domain.com")
//	r.Host("{subdomain:[a-z]+}.domain.com")
//
// Variable names must be unique in a given route. They can be retrieved
// calling mux.Vars(request).
func (r *Route) Host(tpl string) *Route {
	r.err = r.addRegexpMatcher(tpl, regexpTypeHost)
	return r
}

// MatcherFunc ----------------------------------------------------------------

// MatcherFunc is the function signature used by custom matchers.
type MatcherFunc func(*http.Request, *RouteMatch) bool

// Match returns the match for a given request.
func (m MatcherFunc) Match(r *http.Request, match *RouteMatch) bool {
	return m(r, match)
}

// MatcherFunc adds a custom function to be used as request matcher.
func (r *Route) MatcherFunc(f MatcherFunc) *Route {
	return r.addMatcher(f)
}

// Methods --------------------------------------------------------------------

// methodMatcher matches the request against HTTP methods.
type methodMatcher []string

func (m methodMatcher) Match(r *http.Request, match *RouteMatch) bool {
	return matchInArray(m, r.Method)
}

// Methods adds a matcher for HTTP methods.
// It accepts a sequence of one or more methods to be matched, e.g.:
// "GET", "POST", "PUT".
func (r *Route) Methods(methods ...string) *Route {
	for k, v := range methods {
		methods[k] = strings.ToUpper(v)
	}
	return r.addMatcher(methodMatcher(methods))
}

// Path -----------------------------------------------------------------------

// Path adds a matcher for the URL path.
// It accepts a template with zero or more URL variables enclosed by {}. The
// template must start with a "/".
// Variables can define an optional regexp pattern to be matched:
//
// - {name} matches anything until the next slash.
//
// - {name:pattern} matches the given regexp pattern.
//
// For example:
//
//	r := mux.NewRouter().NewRoute()
//	r.Path("/products/").Handler(ProductsHandler)
//	r.Path("/products/{key}").Handler(ProductsHandler)
//	r.Path("/articles/{category}/{id:[0-9]+}").
//	  Handler(ArticleHandler)
//
// Variable names must be unique in a given route. They can be retrieved
// calling mux.Vars(request).
func (r *Route) Path(tpl string) *Route {
	r.err = r.addRegexpMatcher(tpl, regexpTypePath)
	return r
}

// PathPrefix -----------------------------------------------------------------

// PathPrefix adds a matcher for the URL path prefix. This matches if the given
// template is a prefix of the full URL path. See Route.Path() for details on
// the tpl argument.
//
// Note that it does not treat slashes specially ("/foobar/" will be matched by
// the prefix "/foo") so you may want to use a trailing slash here.
//
// Also note that the setting of Router.StrictSlash() has no effect on routes
// with a PathPrefix matcher.
func (r *Route) PathPrefix(tpl string) *Route {
	r.err = r.addRegexpMatcher(tpl, regexpTypePrefix)
	return r
}

// Query ----------------------------------------------------------------------

// Queries adds a matcher for URL query values.
// It accepts a sequence of key/value pairs. Values may define variables.
// For example:
//
//	r := mux.NewRouter().NewRoute()
//	r.Queries("foo", "bar", "id", "{id:[0-9]+}")
//
// The above route will only match if the URL contains the defined queries
// values, e.g.: ?foo=bar&id=42.
//
// If the value is an empty string, it will match any value if the key is set.
//
// Variables can define an optional regexp pattern to be matched:
//
// - {name} matches anything until the next slash.
//
// - {name:pattern} matches the given regexp pattern.
func (r *Route) Queries(pairs ...string) *Route {
	length := len(pairs)
	if length%2 != 0 {
		r.err = fmt.Errorf(
			"mux: number of parameters must be multiple of 2, got %v", pairs)
		return nil
	}
	for i := 0; i < length; i += 2 {
		if r.err = r.addRegexpMatcher(pairs[i]+"="+pairs[i+1], regexpTypeQuery); r.err != nil {
			return r
		}
	}

	return r
}

// Schemes --------------------------------------------------------------------

// schemeMatcher matches the request against URL schemes.
type schemeMatcher []string

func (m schemeMatcher) Match(r *http.Request, match *RouteMatch) bool {
	scheme := r.URL.Scheme
	// https://golang.org/pkg/net/http/#Request
	// "For [most] server requests, fields other than Path and RawQuery will be
	// empty."
	// Since we're an http muxer, the scheme is either going to be http or https
	// though, so we can just set it based on the tls termination state.
	if scheme == "" {
		if r.TLS == nil {
			scheme = "http"
		} else {
			scheme = "https"
		}
	}
	return matchInArray(m, scheme)
}

// Schemes adds a matcher for URL schemes.
// It accepts a sequence of schemes to be matched, e.g.: "http", "https".
// If the request's URL has a scheme set, it will be matched against.
// Generally, the URL scheme will only be set if a previous handler set it,
// such as the ProxyHeaders handler from gorilla/handlers.
// If unset, the scheme will be determined based on the request's TLS
// termination state.
// The first argument to Schemes will be used when constructing a route URL.
func (r *Route) Schemes(schemes ...string) *Route {
	for k, v := range schemes {
		schemes[k] = strings.ToLower(v)
	}
	if len(schemes) > 0 {
		r.buildScheme = schemes[0]
	}
	return r.addMatcher(schemeMatcher(schemes))
}

// BuildVarsFunc --------------------------------------------------------------

// BuildVarsFunc is the function signature used by custom build variable
// functions (which can modify route variables before a route's URL is built).
type BuildVarsFunc func(map[string]string) map[string]string

// BuildVarsFunc adds a custom function to be used to modify build variables
// before a route's URL is built.
func (r *Route) BuildVarsFunc(f BuildVarsFunc) *Route {
	if r.buildVarsFunc != nil {
		// compose the old and new functions
		old := r.buildVarsFunc
		r.buildVarsFunc = func(m map[string]string) map[string]string {
			return f(old(m))
		}
	} else {
		r.buildVarsFunc = f
	}
	return r
}

// Subrouter ------------------------------------------------------------------

// Subrouter creates a subrouter for the route.
//
// It will test the inner routes only if the parent route matched. For example:
//
//	r := mux.NewRouter().NewRoute()
//	s := r.Host("www.example.com").Subrouter()
//	s.HandleFunc("/products/", ProductsHandler)
//	s.HandleFunc("/products/{key}", ProductHandler)
//	s.HandleFunc("/articles/{category}/{id:[0-9]+}"), ArticleHandler)
//
// Here, the routes registered in the subrouter won't be tested if the host
// doesn't match.
func (r *Route) Subrouter() *Router {
	// initialize a subrouter with a copy of the parent route's configuration
	router := &Router{routeConf: copyRouteConf(r.routeConf), namedRoutes: r.namedRoutes}
	r.addMatcher(router)
	return router
}

// ----------------------------------------------------------------------------
// URL building
// ----------------------------------------------------------------------------

// URL builds a URL for the route.
//
// It accepts a sequence of key/value pairs for the route variables. For
// example, given this route:
//
//	r := mux.NewRouter()
//	r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler).
//	  Name("article")
//
// ...a URL for it can be built using:
//
//	url, err := r.Get("article").URL("category", "technology", "id", "42")
//
// ...which will return an url.URL with the following path:
//
//	"/articles/technology/42"
//
// This also works for host variables:
//
//	r := mux.NewRouter()
//	r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler).
//	  Host("{subdomain}.domain.com").
//	  Name("article")
//
//	// url.String() will be "http://news.domain.com/articles/technology/42"
//	url, err := r.Get("article").URL("subdomain", "news",
//	                                 "category", "technology",
//	                                 "id", "42")
//
// The scheme of the resulting url will be the first argument that was passed to Schemes:
//
//	// url.String() will be "https://example.com"
//	r := mux.NewRouter().NewRoute()
//	url, err := r.Host("example.com")
//	             .Schemes("https", "http").URL()
//
// All variables defined in the route are required, and their values must
// conform to the corresponding patterns.
func (r *Route) URL(pairs ...string) (*url.URL, error) {
	if r.err != nil {
		return nil, r.err
	}
	values, err := r.prepareVars(pairs...)
	if err != nil {
		return nil, err
	}
	var scheme, host, path string
	queries := make([]string, 0, len(r.regexp.queries))
	if r.regexp.host != nil {
		if host, err = r.regexp.host.url(values); err != nil {
			return nil, err
		}
		scheme = "http"
		if r.buildScheme != "" {
			scheme = r.buildScheme
		}
	}
	if r.regexp.path != nil {
		if path, err = r.regexp.path.url(values); err != nil {
			return nil, err
		}
	}
	for _, q := range r.regexp.queries {
		var query string
		if query, err = q.url(values); err != nil {
			return nil, err
		}
		queries = append(queries, query)
	}
	return &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     path,
		RawQuery: strings.Join(queries, "&"),
	}, nil
}

// URLHost builds the host part of the URL for a route. See Route.URL().
//
// The route must have a host defined.
func (r *Route) URLHost(pairs ...string) (*url.URL, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.regexp.host == nil {
		return nil, errors.New("mux: route doesn't have a host")
	}
	values, err := r.prepareVars(pairs...)
	if err != nil {
		return nil, err
	}
	host, err := r.regexp.host.url(values)
	if err != nil {
		return nil, err
	}
	u := &url.URL{
		Scheme: "http",
		Host:   host,
	}
	if r.buildScheme != "" {
		u.Scheme = r.buildScheme
	}
	return u, nil
}

// URLPath builds the path part of the URL for a route. See Route.URL().
//
// The route must have a path defined.
func (r *Route) URLPath(pairs ...string) (*url.URL, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.regexp.path == nil {
		return nil, errors.New("mux: route doesn't have a path")
	}
	values, err := r.prepareVars(pairs...)
	if err != nil {
		return nil, err
	}
	path, err := r.regexp.path.url(values)
	if err != nil {
		return nil, err
	}
	return &url.URL{
		Path: path,
	}, nil
}

// GetPathTemplate returns the template used to build the
// route match.
// This is useful for building simple REST API documentation and for instrumentation
// against third-party services.
// An error will be returned if the route does not define a path.
func (r *Route) GetPathTemplate() (string, error) {
	if r.err != nil {
		return "", r.err
	}
	if r.regexp.path == nil {
		return "", errors.New("mux: route doesn't have a path")
	}
	return r.regexp.path.template, nil
}

// GetPathRegexp returns the expanded regular expression used to match route path.
// This is useful for building simple REST API documentation and for instrumentation
// against third-party services.
// An error will be returned if the route does not define a path.
func (r *Route) GetPathRegexp() (string, error) {
	if r.err != nil {
		return "", r.err
	}
	if r.regexp.path == nil {
		return "", errors.New("mux: route does not have a path")
	}
	return r.regexp.path.regexp.String(), nil
}

// GetQueriesRegexp returns the expanded regular expressions used to match the
// route queries.
// This is useful for building simple REST API documentation and for instrumentation
// against third-party services.
// An error will be returned if the route does not have queries.
func (r *Route) GetQueriesRegexp() ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.regexp.queries == nil {
		return nil, errors.New("mux: route doesn't have queries")
	}
	queries := make([]string, 0, len(r.regexp.queries))
	for _, query := range r.regexp.queries {
		queries = append(queries, query.regexp.String())
	}
	return queries, nil
}

// GetQueriesTemplates returns the templates used to build the
// query matching.
// This is useful for building simple REST API documentation and for instrumentation
// against third-party services.
// An error will be returned if the route does not define queries.
func (r *Route) GetQueriesTemplates() ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.regexp.queries == nil {
		return nil, errors.New("mux: route doesn't have queries")
	}
	queries := make([]string, 0, len(r.regexp.queries))
	for _, query := range r.regexp.queries {
		queries = append(queries, query.template)
	}
	return queries, nil
}

// GetMethods returns the methods the route matches against
// This is useful for building simple REST API documentation and for instrumentation
// against third-party services.
// An error will be returned if route does not have methods.
func (r *Route) GetMethods() ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	for _, m := range r.matchers {
		if methods, ok := m.(methodMatcher); ok {
			return []string(methods), nil
		}
	}
	return nil, errors.New("mux: route doesn't have methods")
}

// GetHostTemplate returns the template used to build the
// route match.
// This is useful for building simple REST API documentation and for instrumentation
// against third-party services.
// An error will be returned if the route does not define a host.
func (r *Route) GetHostTemplate() (string, error) {
	if r.err != nil {
		return "", r.err
	}
	if r.regexp.host == nil {
		return "", errors.New("mux: route doesn't have a host")
	}
	return r.regexp.host.template, nil
}

// GetVarNames returns the names of all variables added by regexp matchers
// These can be used to know which route variables should be passed into r.URL()
func (r *Route) GetVarNames() ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	var varNames []string
	if r.regexp.host != nil {
		varNames = append(varNames, r.regexp.host.varsN...)
	}
	if r.regexp.path != nil {
		varNames = append(varNames, r.regexp.path.varsN...)
	}
	for _, regx := range r.regexp.queries {
		varNames = append(varNames, regx.varsN...)
	}
	return varNames, nil
}

// prepareVars converts the route variable pairs into a map. If the route has a
// BuildVarsFunc, it is invoked.
func (r *Route) prepareVars(pairs ...string) (map[string]string, error) {
	m, err := mapFromPairsToString(pairs...)
	if err != nil {
		return nil, err
	}
	return r.buildVars(m), nil
}

func (r *Route) buildVars(m map[string]string) map[string]string {
	if r.buildVarsFunc != nil {
		m = r.buildVarsFunc(m)
	}
	return m
}
"#,
    ),
    (
        "test_helpers.go",
        r#"// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mux

import "net/http"

// SetURLVars sets the URL variables for the given request, to be accessed via
// mux.Vars for testing route behaviour. Arguments are not modified, a shallow
// copy is returned.
//
// This API should only be used for testing purposes; it provides a way to
// inject variables into the request context. Alternatively, URL variables
// can be set by making a route that captures the required variables,
// starting a server and sending the request to that server.
func SetURLVars(r *http.Request, val map[string]string) *http.Request {
	return requestWithVars(r, val)
}
"#,
    ),
];
const FILE_LOCAL_SOURCES: &[(&str, &str)] = &[
    (
        "src/method_assertion_clean/program.go",
        r#"package p

type Router struct{}

func (*Router) fail() error { return nil }
func check(values []any) {
	for _, value := range values {
		if r, ok := value.(*Router); ok {
			problem := r.fail()
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
			if problem != nil {
				println(problem)
			}
		}
	}
}
"#,
    ),
    (
        "src/method_error_clean/program.go",
        r#"package p

type Router struct{}

func (*Router) fail() error { return nil }
func check(r *Router) {
	problem := r.fail()
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
}
"#,
    ),
    (
        "src/method_pointer_positive/program.go",
        r#"package p

type Router struct{}
type Other struct{}

func (*Router) fail() error { return nil }
func (*Other) fail() *int   { return nil }
func check(r *Other) {
	problem := r.fail()
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
}
"#,
    ),
    (
        "src/method_tuple_positive/program.go",
        r#"package p

type Router struct{}

func (*Router) results() (error, *int) { return nil, nil }
func check(r *Router) {
	good, problem := r.results()
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if good != nil {
		println(good)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
}
"#,
    ),
    (
        "src/ordinary_error_clean/program.go",
        r#"package p

func failure() error { return nil }
func check() {
	problem := failure()
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
}
"#,
    ),
    (
        "src/selector_positive/program.go",
        r#"package p

type Router struct{ err error }

func check(r *Router) {
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
	if r.err != nil {
		println(r.err)
	}
}
"#,
    ),
    (
        "src/url_else_positive/program.go",
        r#"package p

import "net/url"

func check() {
	_, problem := url.QueryUnescape("x")
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
	if problem != nil {
		println(problem)
	} else {
		println(1)
	}
}
"#,
    ),
    (
        "src/url_error_clean/program.go",
        r#"package p

import uri "net/url"

func check() {
	_, problem := uri.QueryUnescape("x")
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
}
"#,
    ),
    (
        "src/url_local_shadow_positive/program.go",
        r#"package p

import uri "net/url"

var _ = uri.QueryUnescape

func check() {
	uri := struct{ QueryUnescape func(string) (string, *int) }{}
	_, problem := uri.QueryUnescape("x")
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
}
"#,
    ),
    (
        "src/url_nested_control_positive/program.go",
        r#"package p

import "net/url"

func check(flag bool) {
	_, problem := url.QueryUnescape("x")
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
	if problem != nil {
		if flag {
			println(problem)
		}
	}
}
"#,
    ),
    (
        "src/url_shadow_positive/program.go",
        r#"package p

import "net/url"

var _ = url.QueryUnescape

func check(url interface{ QueryUnescape(string) (string, *int) }) {
	_, problem := url.QueryUnescape("x")
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
	if problem != nil {
		println(problem)
	}
}
"#,
    ),
];

const MUX_NATIVE: &str = r#"{"schema_version":1,"files":[{"path":"./doc.go","language":"go","issues":[{"rule_key":"go:S103","message":"Split this 411 characters long line (which is greater than 120 authorized).","range":{"start":{"line":242,"column":0},"end":{"line":242,"column":411}}},{"rule_key":"go:S103","message":"Split this 267 characters long line (which is greater than 120 authorized).","range":{"start":{"line":246,"column":0},"end":{"line":246,"column":267}}},{"rule_key":"go:S103","message":"Split this 196 characters long line (which is greater than 120 authorized).","range":{"start":{"line":303,"column":0},"end":{"line":303,"column":196}}}],"metrics":{"lines":306,"code_lines":1,"comment_lines":221}},{"path":"./middleware.go","language":"go","issues":[{"rule_key":"go:S103","message":"Split this 121 characters long line (which is greater than 120 authorized).","range":{"start":{"line":9,"column":0},"end":{"line":9,"column":121}}},{"rule_key":"go:S103","message":"Split this 195 characters long line (which is greater than 120 authorized).","range":{"start":{"line":23,"column":0},"end":{"line":23,"column":195}}},{"rule_key":"go:S103","message":"Split this 200 characters long line (which is greater than 120 authorized).","range":{"start":{"line":30,"column":0},"end":{"line":30,"column":200}}},{"rule_key":"go:S103","message":"Split this 282 characters long line (which is greater than 120 authorized).","range":{"start":{"line":37,"column":0},"end":{"line":37,"column":282}}},{"rule_key":"go:S103","message":"Split this 291 characters long line (which is greater than 120 authorized).","range":{"start":{"line":46,"column":0},"end":{"line":46,"column":291}}}],"metrics":{"lines":91,"code_lines":58,"comment_lines":16}},{"path":"./mux.go","language":"go","issues":[{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 18 to the 15 allowed.","range":{"start":{"line":188,"column":17},"end":{"line":188,"column":26}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":189,"column":1},"end":{"line":189,"column":3}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":191,"column":2},"end":{"line":191,"column":4}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":195,"column":2},"end":{"line":195,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":203,"column":1},"end":{"line":203,"column":3}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":205,"column":2},"end":{"line":205,"column":4}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":207,"column":3},"end":{"line":207,"column":5}}}]},{"locations":[{"message":"+1","range":{"start":{"line":210,"column":5},"end":{"line":210,"column":9}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":214,"column":3},"end":{"line":214,"column":5}}}]},{"locations":[{"message":"+1","range":{"start":{"line":220,"column":1},"end":{"line":220,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":220,"column":19},"end":{"line":220,"column":21}}}]},{"locations":[{"message":"+1","range":{"start":{"line":224,"column":1},"end":{"line":224,"column":3}}}]}]},{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","range":{"start":{"line":615,"column":5},"end":{"line":615,"column":23}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":616,"column":1},"end":{"line":616,"column":4}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":618,"column":2},"end":{"line":618,"column":4}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":621,"column":2},"end":{"line":621,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":623,"column":4},"end":{"line":623,"column":8}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":627,"column":3},"end":{"line":627,"column":6}}}]},{"locations":[{"message":"+4 (incl 3 for nesting)","range":{"start":{"line":628,"column":4},"end":{"line":628,"column":6}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":633,"column":3},"end":{"line":633,"column":5}}}]}]},{"rule_key":"go:S126","message":"Add the missing \"else\" clause.","range":{"start":{"line":623,"column":4},"end":{"line":623,"column":11}}},{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","range":{"start":{"line":643,"column":5},"end":{"line":643,"column":22}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":644,"column":1},"end":{"line":644,"column":4}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":646,"column":2},"end":{"line":646,"column":4}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":649,"column":2},"end":{"line":649,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":651,"column":4},"end":{"line":651,"column":8}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":655,"column":3},"end":{"line":655,"column":6}}}]},{"locations":[{"message":"+4 (incl 3 for nesting)","range":{"start":{"line":656,"column":4},"end":{"line":656,"column":6}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":661,"column":3},"end":{"line":661,"column":5}}}]}]},{"rule_key":"go:S126","message":"Add the missing \"else\" clause.","range":{"start":{"line":651,"column":4},"end":{"line":651,"column":11}}}],"metrics":{"lines":677,"code_lines":389,"comment_lines":174}},{"path":"./regexp.go","language":"go","issues":[{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 22 to the 15 allowed.","range":{"start":{"line":41,"column":5},"end":{"line":41,"column":19}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":51,"column":1},"end":{"line":51,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":53,"column":3},"end":{"line":53,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":57,"column":1},"end":{"line":57,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":62,"column":1},"end":{"line":62,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":62,"column":24},"end":{"line":62,"column":26}}}]},{"locations":[{"message":"+1","range":{"start":{"line":75,"column":1},"end":{"line":75,"column":4}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":87,"column":2},"end":{"line":87,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":90,"column":4},"end":{"line":90,"column":8}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":96,"column":2},"end":{"line":96,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":96,"column":16},"end":{"line":96,"column":18}}}]},{"locations":[{"message":"+1","range":{"start":{"line":117,"column":1},"end":{"line":117,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":120,"column":1},"end":{"line":120,"column":3}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":122,"column":2},"end":{"line":122,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":126,"column":1},"end":{"line":126,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":138,"column":1},"end":{"line":138,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":144,"column":1},"end":{"line":144,"column":3}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":145,"column":2},"end":{"line":145,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":150,"column":1},"end":{"line":150,"column":3}}}]}]},{"rule_key":"go:S126","message":"Add the missing \"else\" clause.","range":{"start":{"line":53,"column":3},"end":{"line":53,"column":10}}},{"rule_key":"go:S131","message":"Add a default clause to this \"switch\" statement.","range":{"start":{"line":303,"column":2},"end":{"line":303,"column":8}}},{"rule_key":"go:S126","message":"Add the missing \"else\" clause.","range":{"start":{"line":311,"column":5},"end":{"line":311,"column":12}}},{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 36 to the 15 allowed.","range":{"start":{"line":339,"column":26},"end":{"line":339,"column":34}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":341,"column":1},"end":{"line":341,"column":3}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":342,"column":2},"end":{"line":342,"column":4}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":344,"column":3},"end":{"line":344,"column":5}}}]},{"locations":[{"message":"+4 (incl 3 for nesting)","range":{"start":{"line":346,"column":4},"end":{"line":346,"column":6}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":351,"column":3},"end":{"line":351,"column":5}}}]},{"locations":[{"message":"+1","range":{"start":{"line":357,"column":1},"end":{"line":357,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":361,"column":1},"end":{"line":361,"column":3}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":362,"column":2},"end":{"line":362,"column":4}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":364,"column":3},"end":{"line":364,"column":5}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":369,"column":2},"end":{"line":369,"column":4}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":372,"column":3},"end":{"line":372,"column":5}}}]},{"locations":[{"message":"+4 (incl 3 for nesting)","range":{"start":{"line":374,"column":4},"end":{"line":374,"column":6}}}]},{"locations":[{"message":"+1","range":{"start":{"line":376,"column":6},"end":{"line":376,"column":10}}}]},{"locations":[{"message":"+1","range":{"start":{"line":385,"column":1},"end":{"line":385,"column":4}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":386,"column":2},"end":{"line":386,"column":4}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":389,"column":3},"end":{"line":389,"column":5}}}]}]}],"metrics":{"lines":415,"code_lines":314,"comment_lines":63}},{"path":"./route.go","language":"go","issues":[{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 22 to the 15 allowed.","range":{"start":{"line":47,"column":16},"end":{"line":47,"column":21}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":48,"column":1},"end":{"line":48,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":48,"column":16},"end":{"line":48,"column":18}}}]},{"locations":[{"message":"+1","range":{"start":{"line":55,"column":1},"end":{"line":55,"column":4}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":56,"column":2},"end":{"line":56,"column":4}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":57,"column":3},"end":{"line":57,"column":5}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":68,"column":3},"end":{"line":68,"column":5}}}]},{"locations":[{"message":"+4 (incl 3 for nesting)","range":{"start":{"line":69,"column":4},"end":{"line":69,"column":6}}}]},{"locations":[{"message":"+3 (incl 2 for nesting)","range":{"start":{"line":82,"column":3},"end":{"line":82,"column":5}}}]},{"locations":[{"message":"+1","range":{"start":{"line":96,"column":1},"end":{"line":96,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":96,"column":26},"end":{"line":96,"column":28}}}]},{"locations":[{"message":"+1","range":{"start":{"line":104,"column":1},"end":{"line":104,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":107,"column":1},"end":{"line":107,"column":3}}}]}]},{"rule_key":"go:S103","message":"Split this 152 characters long line (which is greater than 120 authorized).","range":{"start":{"line":154,"column":0},"end":{"line":154,"column":152}}},{"rule_key":"go:S103","message":"Split this 151 characters long line (which is greater than 120 authorized).","range":{"start":{"line":164,"column":0},"end":{"line":164,"column":151}}},{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 18 to the 15 allowed.","range":{"start":{"line":247,"column":16},"end":{"line":247,"column":32}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":248,"column":1},"end":{"line":248,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":251,"column":1},"end":{"line":251,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":251,"column":26},"end":{"line":251,"column":28}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":252,"column":2},"end":{"line":252,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":252,"column":18},"end":{"line":252,"column":20}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":255,"column":2},"end":{"line":255,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":266,"column":1},"end":{"line":266,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":271,"column":1},"end":{"line":271,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":278,"column":3},"end":{"line":278,"column":7}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":272,"column":2},"end":{"line":272,"column":4}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":279,"column":2},"end":{"line":279,"column":4}}}]},{"locations":[{"message":"+2 (incl 1 for nesting)","range":{"start":{"line":284,"column":2},"end":{"line":284,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":286,"column":4},"end":{"line":286,"column":8}}}]}]}],"metrics":{"lines":829,"code_lines":467,"comment_lines":225}},{"path":"./test_helpers.go","language":"go","issues":[],"metrics":{"lines":20,"code_lines":5,"comment_lines":10}}],"project":{"metrics":{"files":6,"lines":2338,"code_lines":1234,"comment_lines":709},"files":[{"path":"./bench_test.go","classification":"excluded","status":"excluded","metrics":null,"duplication":null,"reason":"explicitly excluded"},{"path":"./doc.go","classification":"source","status":"complete","metrics":{"lines":306,"code_lines":1,"comment_lines":221},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./example_authentication_middleware_test.go","classification":"excluded","status":"excluded","metrics":null,"duplication":null,"reason":"explicitly excluded"},{"path":"./example_cors_method_middleware_test.go","classification":"excluded","status":"excluded","metrics":null,"duplication":null,"reason":"explicitly excluded"},{"path":"./example_route_test.go","classification":"excluded","status":"excluded","metrics":null,"duplication":null,"reason":"explicitly excluded"},{"path":"./example_route_vars_test.go","classification":"excluded","status":"excluded","metrics":null,"duplication":null,"reason":"explicitly excluded"},{"path":"./middleware.go","classification":"source","status":"complete","metrics":{"lines":91,"code_lines":58,"comment_lines":16},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./middleware_test.go","classification":"excluded","status":"excluded","metrics":null,"duplication":null,"reason":"explicitly excluded"},{"path":"./mux.go","classification":"source","status":"complete","metrics":{"lines":677,"code_lines":389,"comment_lines":174},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./mux_httpserver_test.go","classification":"excluded","status":"excluded","metrics":null,"duplication":null,"reason":"explicitly excluded"},{"path":"./mux_test.go","classification":"excluded","status":"excluded","metrics":null,"duplication":null,"reason":"explicitly excluded"},{"path":"./old_test.go","classification":"excluded","status":"excluded","metrics":null,"duplication":null,"reason":"explicitly excluded"},{"path":"./regexp.go","classification":"source","status":"complete","metrics":{"lines":415,"code_lines":314,"comment_lines":63},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./regexp_test.go","classification":"excluded","status":"excluded","metrics":null,"duplication":null,"reason":"explicitly excluded"},{"path":"./route.go","classification":"source","status":"complete","metrics":{"lines":829,"code_lines":467,"comment_lines":225},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null},{"path":"./route_test.go","classification":"excluded","status":"excluded","metrics":null,"duplication":null,"reason":"explicitly excluded"},{"path":"./test_helpers.go","classification":"source","status":"complete","metrics":{"lines":20,"code_lines":5,"comment_lines":10},"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"reason":null}],"duplications":[],"duplication":{"duplicated_lines":0,"duplicated_blocks":0,"duplicated_files":0,"duplicated_lines_density":0.0},"complete":true,"warnings":[],"roots":["."]}}"#;

const MUX_GENERIC: &str = r#"{"issues":[{"primaryLocation":{"filePath":"./doc.go","message":"Split this 411 characters long line (which is greater than 120 authorized).","textRange":{"endColumn":411,"endLine":242,"startColumn":0,"startLine":242}},"ruleId":"go:S103"},{"primaryLocation":{"filePath":"./doc.go","message":"Split this 267 characters long line (which is greater than 120 authorized).","textRange":{"endColumn":267,"endLine":246,"startColumn":0,"startLine":246}},"ruleId":"go:S103"},{"primaryLocation":{"filePath":"./doc.go","message":"Split this 196 characters long line (which is greater than 120 authorized).","textRange":{"endColumn":196,"endLine":303,"startColumn":0,"startLine":303}},"ruleId":"go:S103"},{"primaryLocation":{"filePath":"./middleware.go","message":"Split this 121 characters long line (which is greater than 120 authorized).","textRange":{"endColumn":121,"endLine":9,"startColumn":0,"startLine":9}},"ruleId":"go:S103"},{"primaryLocation":{"filePath":"./middleware.go","message":"Split this 195 characters long line (which is greater than 120 authorized).","textRange":{"endColumn":195,"endLine":23,"startColumn":0,"startLine":23}},"ruleId":"go:S103"},{"primaryLocation":{"filePath":"./middleware.go","message":"Split this 200 characters long line (which is greater than 120 authorized).","textRange":{"endColumn":200,"endLine":30,"startColumn":0,"startLine":30}},"ruleId":"go:S103"},{"primaryLocation":{"filePath":"./middleware.go","message":"Split this 282 characters long line (which is greater than 120 authorized).","textRange":{"endColumn":282,"endLine":37,"startColumn":0,"startLine":37}},"ruleId":"go:S103"},{"primaryLocation":{"filePath":"./middleware.go","message":"Split this 291 characters long line (which is greater than 120 authorized).","textRange":{"endColumn":291,"endLine":46,"startColumn":0,"startLine":46}},"ruleId":"go:S103"},{"primaryLocation":{"filePath":"./mux.go","message":"Refactor this method to reduce its Cognitive Complexity from 18 to the 15 allowed.","textRange":{"endColumn":26,"endLine":188,"startColumn":17,"startLine":188}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"./mux.go","message":"+1","textRange":{"endColumn":3,"endLine":189,"startColumn":1,"startLine":189}},{"filePath":"./mux.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":191,"startColumn":2,"startLine":191}},{"filePath":"./mux.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":195,"startColumn":2,"startLine":195}},{"filePath":"./mux.go","message":"+1","textRange":{"endColumn":3,"endLine":203,"startColumn":1,"startLine":203}},{"filePath":"./mux.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":205,"startColumn":2,"startLine":205}},{"filePath":"./mux.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":207,"startColumn":3,"startLine":207}},{"filePath":"./mux.go","message":"+1","textRange":{"endColumn":9,"endLine":210,"startColumn":5,"startLine":210}},{"filePath":"./mux.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":214,"startColumn":3,"startLine":214}},{"filePath":"./mux.go","message":"+1","textRange":{"endColumn":3,"endLine":220,"startColumn":1,"startLine":220}},{"filePath":"./mux.go","message":"+1","textRange":{"endColumn":21,"endLine":220,"startColumn":19,"startLine":220}},{"filePath":"./mux.go","message":"+1","textRange":{"endColumn":3,"endLine":224,"startColumn":1,"startLine":224}}]},{"primaryLocation":{"filePath":"./mux.go","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","textRange":{"endColumn":23,"endLine":615,"startColumn":5,"startLine":615}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"./mux.go","message":"+1","textRange":{"endColumn":4,"endLine":616,"startColumn":1,"startLine":616}},{"filePath":"./mux.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":618,"startColumn":2,"startLine":618}},{"filePath":"./mux.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":621,"startColumn":2,"startLine":621}},{"filePath":"./mux.go","message":"+1","textRange":{"endColumn":8,"endLine":623,"startColumn":4,"startLine":623}},{"filePath":"./mux.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":6,"endLine":627,"startColumn":3,"startLine":627}},{"filePath":"./mux.go","message":"+4 (incl 3 for nesting)","textRange":{"endColumn":6,"endLine":628,"startColumn":4,"startLine":628}},{"filePath":"./mux.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":633,"startColumn":3,"startLine":633}}]},{"primaryLocation":{"filePath":"./mux.go","message":"Add the missing \"else\" clause.","textRange":{"endColumn":11,"endLine":623,"startColumn":4,"startLine":623}},"ruleId":"go:S126"},{"primaryLocation":{"filePath":"./mux.go","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","textRange":{"endColumn":22,"endLine":643,"startColumn":5,"startLine":643}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"./mux.go","message":"+1","textRange":{"endColumn":4,"endLine":644,"startColumn":1,"startLine":644}},{"filePath":"./mux.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":646,"startColumn":2,"startLine":646}},{"filePath":"./mux.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":649,"startColumn":2,"startLine":649}},{"filePath":"./mux.go","message":"+1","textRange":{"endColumn":8,"endLine":651,"startColumn":4,"startLine":651}},{"filePath":"./mux.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":6,"endLine":655,"startColumn":3,"startLine":655}},{"filePath":"./mux.go","message":"+4 (incl 3 for nesting)","textRange":{"endColumn":6,"endLine":656,"startColumn":4,"startLine":656}},{"filePath":"./mux.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":661,"startColumn":3,"startLine":661}}]},{"primaryLocation":{"filePath":"./mux.go","message":"Add the missing \"else\" clause.","textRange":{"endColumn":11,"endLine":651,"startColumn":4,"startLine":651}},"ruleId":"go:S126"},{"primaryLocation":{"filePath":"./regexp.go","message":"Refactor this method to reduce its Cognitive Complexity from 22 to the 15 allowed.","textRange":{"endColumn":19,"endLine":41,"startColumn":5,"startLine":41}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":3,"endLine":51,"startColumn":1,"startLine":51}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":7,"endLine":53,"startColumn":3,"startLine":53}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":3,"endLine":57,"startColumn":1,"startLine":57}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":3,"endLine":62,"startColumn":1,"startLine":62}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":26,"endLine":62,"startColumn":24,"startLine":62}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":4,"endLine":75,"startColumn":1,"startLine":75}},{"filePath":"./regexp.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":87,"startColumn":2,"startLine":87}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":8,"endLine":90,"startColumn":4,"startLine":90}},{"filePath":"./regexp.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":96,"startColumn":2,"startLine":96}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":18,"endLine":96,"startColumn":16,"startLine":96}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":3,"endLine":117,"startColumn":1,"startLine":117}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":3,"endLine":120,"startColumn":1,"startLine":120}},{"filePath":"./regexp.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":122,"startColumn":2,"startLine":122}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":3,"endLine":126,"startColumn":1,"startLine":126}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":3,"endLine":138,"startColumn":1,"startLine":138}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":3,"endLine":144,"startColumn":1,"startLine":144}},{"filePath":"./regexp.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":145,"startColumn":2,"startLine":145}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":3,"endLine":150,"startColumn":1,"startLine":150}}]},{"primaryLocation":{"filePath":"./regexp.go","message":"Add the missing \"else\" clause.","textRange":{"endColumn":10,"endLine":53,"startColumn":3,"startLine":53}},"ruleId":"go:S126"},{"primaryLocation":{"filePath":"./regexp.go","message":"Add a default clause to this \"switch\" statement.","textRange":{"endColumn":8,"endLine":303,"startColumn":2,"startLine":303}},"ruleId":"go:S131"},{"primaryLocation":{"filePath":"./regexp.go","message":"Add the missing \"else\" clause.","textRange":{"endColumn":12,"endLine":311,"startColumn":5,"startLine":311}},"ruleId":"go:S126"},{"primaryLocation":{"filePath":"./regexp.go","message":"Refactor this method to reduce its Cognitive Complexity from 36 to the 15 allowed.","textRange":{"endColumn":34,"endLine":339,"startColumn":26,"startLine":339}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":3,"endLine":341,"startColumn":1,"startLine":341}},{"filePath":"./regexp.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":342,"startColumn":2,"startLine":342}},{"filePath":"./regexp.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":344,"startColumn":3,"startLine":344}},{"filePath":"./regexp.go","message":"+4 (incl 3 for nesting)","textRange":{"endColumn":6,"endLine":346,"startColumn":4,"startLine":346}},{"filePath":"./regexp.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":351,"startColumn":3,"startLine":351}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":3,"endLine":357,"startColumn":1,"startLine":357}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":3,"endLine":361,"startColumn":1,"startLine":361}},{"filePath":"./regexp.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":362,"startColumn":2,"startLine":362}},{"filePath":"./regexp.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":364,"startColumn":3,"startLine":364}},{"filePath":"./regexp.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":369,"startColumn":2,"startLine":369}},{"filePath":"./regexp.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":372,"startColumn":3,"startLine":372}},{"filePath":"./regexp.go","message":"+4 (incl 3 for nesting)","textRange":{"endColumn":6,"endLine":374,"startColumn":4,"startLine":374}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":10,"endLine":376,"startColumn":6,"startLine":376}},{"filePath":"./regexp.go","message":"+1","textRange":{"endColumn":4,"endLine":385,"startColumn":1,"startLine":385}},{"filePath":"./regexp.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":386,"startColumn":2,"startLine":386}},{"filePath":"./regexp.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":389,"startColumn":3,"startLine":389}}]},{"primaryLocation":{"filePath":"./route.go","message":"Refactor this method to reduce its Cognitive Complexity from 22 to the 15 allowed.","textRange":{"endColumn":21,"endLine":47,"startColumn":16,"startLine":47}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"./route.go","message":"+1","textRange":{"endColumn":3,"endLine":48,"startColumn":1,"startLine":48}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":18,"endLine":48,"startColumn":16,"startLine":48}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":4,"endLine":55,"startColumn":1,"startLine":55}},{"filePath":"./route.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":56,"startColumn":2,"startLine":56}},{"filePath":"./route.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":57,"startColumn":3,"startLine":57}},{"filePath":"./route.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":68,"startColumn":3,"startLine":68}},{"filePath":"./route.go","message":"+4 (incl 3 for nesting)","textRange":{"endColumn":6,"endLine":69,"startColumn":4,"startLine":69}},{"filePath":"./route.go","message":"+3 (incl 2 for nesting)","textRange":{"endColumn":5,"endLine":82,"startColumn":3,"startLine":82}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":3,"endLine":96,"startColumn":1,"startLine":96}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":28,"endLine":96,"startColumn":26,"startLine":96}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":3,"endLine":104,"startColumn":1,"startLine":104}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":3,"endLine":107,"startColumn":1,"startLine":107}}]},{"primaryLocation":{"filePath":"./route.go","message":"Split this 152 characters long line (which is greater than 120 authorized).","textRange":{"endColumn":152,"endLine":154,"startColumn":0,"startLine":154}},"ruleId":"go:S103"},{"primaryLocation":{"filePath":"./route.go","message":"Split this 151 characters long line (which is greater than 120 authorized).","textRange":{"endColumn":151,"endLine":164,"startColumn":0,"startLine":164}},"ruleId":"go:S103"},{"primaryLocation":{"filePath":"./route.go","message":"Refactor this method to reduce its Cognitive Complexity from 18 to the 15 allowed.","textRange":{"endColumn":32,"endLine":247,"startColumn":16,"startLine":247}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"./route.go","message":"+1","textRange":{"endColumn":3,"endLine":248,"startColumn":1,"startLine":248}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":3,"endLine":251,"startColumn":1,"startLine":251}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":28,"endLine":251,"startColumn":26,"startLine":251}},{"filePath":"./route.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":252,"startColumn":2,"startLine":252}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":20,"endLine":252,"startColumn":18,"startLine":252}},{"filePath":"./route.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":255,"startColumn":2,"startLine":255}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":4,"endLine":266,"startColumn":1,"startLine":266}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":3,"endLine":271,"startColumn":1,"startLine":271}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":7,"endLine":278,"startColumn":3,"startLine":278}},{"filePath":"./route.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":272,"startColumn":2,"startLine":272}},{"filePath":"./route.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":279,"startColumn":2,"startLine":279}},{"filePath":"./route.go","message":"+2 (incl 1 for nesting)","textRange":{"endColumn":4,"endLine":284,"startColumn":2,"startLine":284}},{"filePath":"./route.go","message":"+1","textRange":{"endColumn":8,"endLine":286,"startColumn":4,"startLine":286}}]}],"rules":[{"cleanCodeAttribute":"FORMATTED","description":"Hoonarqube finding for `go:S103`.","engineId":"hoonarqube","id":"go:S103","impacts":[{"severity":"MEDIUM","softwareQuality":"MAINTAINABILITY"}],"name":"go:S103","severity":"MAJOR","type":"CODE_SMELL"},{"cleanCodeAttribute":"CLEAR","description":"Hoonarqube finding for `go:S126`.","engineId":"hoonarqube","id":"go:S126","impacts":[{"severity":"HIGH","softwareQuality":"MAINTAINABILITY"}],"name":"go:S126","severity":"CRITICAL","type":"CODE_SMELL"},{"cleanCodeAttribute":"CLEAR","description":"Hoonarqube finding for `go:S131`.","engineId":"hoonarqube","id":"go:S131","impacts":[{"severity":"HIGH","softwareQuality":"MAINTAINABILITY"}],"name":"go:S131","severity":"CRITICAL","type":"CODE_SMELL"},{"cleanCodeAttribute":"FOCUSED","description":"Hoonarqube finding for `go:S3776`.","engineId":"hoonarqube","id":"go:S3776","impacts":[{"severity":"HIGH","softwareQuality":"MAINTAINABILITY"}],"name":"go:S3776","severity":"CRITICAL","type":"CODE_SMELL"}]}"#;

const FILE_LOCAL_NATIVE: &str = r#"{"schema_version":1,"files":[{"path":"src/method_assertion_clean/program.go","language":"go","issues":[],"metrics":{"lines":61,"code_lines":58,"comment_lines":0}},{"path":"src/method_error_clean/program.go","language":"go","issues":[],"metrics":{"lines":57,"code_lines":54,"comment_lines":0}},{"path":"src/method_pointer_positive/program.go","language":"go","issues":[{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","range":{"start":{"line":8,"column":5},"end":{"line":8,"column":10}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":10,"column":1},"end":{"line":10,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":13,"column":1},"end":{"line":13,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":16,"column":1},"end":{"line":16,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":19,"column":1},"end":{"line":19,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":22,"column":1},"end":{"line":22,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":25,"column":1},"end":{"line":25,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":28,"column":1},"end":{"line":28,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":31,"column":1},"end":{"line":31,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":34,"column":1},"end":{"line":34,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":37,"column":1},"end":{"line":37,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":40,"column":1},"end":{"line":40,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":43,"column":1},"end":{"line":43,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":46,"column":1},"end":{"line":46,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":49,"column":1},"end":{"line":49,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":52,"column":1},"end":{"line":52,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":55,"column":1},"end":{"line":55,"column":3}}}]}]}],"metrics":{"lines":59,"code_lines":56,"comment_lines":0}},{"path":"src/method_tuple_positive/program.go","language":"go","issues":[{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","range":{"start":{"line":6,"column":5},"end":{"line":6,"column":10}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":56,"column":1},"end":{"line":56,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":59,"column":1},"end":{"line":59,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":62,"column":1},"end":{"line":62,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":65,"column":1},"end":{"line":65,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":68,"column":1},"end":{"line":68,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":71,"column":1},"end":{"line":71,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":74,"column":1},"end":{"line":74,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":77,"column":1},"end":{"line":77,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":80,"column":1},"end":{"line":80,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":83,"column":1},"end":{"line":83,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":86,"column":1},"end":{"line":86,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":89,"column":1},"end":{"line":89,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":92,"column":1},"end":{"line":92,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":95,"column":1},"end":{"line":95,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":98,"column":1},"end":{"line":98,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":101,"column":1},"end":{"line":101,"column":3}}}]}]}],"metrics":{"lines":105,"code_lines":102,"comment_lines":0}},{"path":"src/ordinary_error_clean/program.go","language":"go","issues":[],"metrics":{"lines":55,"code_lines":53,"comment_lines":0}},{"path":"src/selector_positive/program.go","language":"go","issues":[{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","range":{"start":{"line":5,"column":5},"end":{"line":5,"column":10}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":6,"column":1},"end":{"line":6,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":9,"column":1},"end":{"line":9,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":12,"column":1},"end":{"line":12,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":15,"column":1},"end":{"line":15,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":18,"column":1},"end":{"line":18,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":21,"column":1},"end":{"line":21,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":24,"column":1},"end":{"line":24,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":27,"column":1},"end":{"line":27,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":30,"column":1},"end":{"line":30,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":33,"column":1},"end":{"line":33,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":36,"column":1},"end":{"line":36,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":39,"column":1},"end":{"line":39,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":42,"column":1},"end":{"line":42,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":45,"column":1},"end":{"line":45,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":48,"column":1},"end":{"line":48,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":51,"column":1},"end":{"line":51,"column":3}}}]}]}],"metrics":{"lines":55,"code_lines":52,"comment_lines":0}},{"path":"src/url_else_positive/program.go","language":"go","issues":[{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 32 to the 15 allowed.","range":{"start":{"line":5,"column":5},"end":{"line":5,"column":10}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":7,"column":1},"end":{"line":7,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":9,"column":3},"end":{"line":9,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":12,"column":1},"end":{"line":12,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":14,"column":3},"end":{"line":14,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":17,"column":1},"end":{"line":17,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":19,"column":3},"end":{"line":19,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":22,"column":1},"end":{"line":22,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":24,"column":3},"end":{"line":24,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":27,"column":1},"end":{"line":27,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":29,"column":3},"end":{"line":29,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":32,"column":1},"end":{"line":32,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":34,"column":3},"end":{"line":34,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":37,"column":1},"end":{"line":37,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":39,"column":3},"end":{"line":39,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":42,"column":1},"end":{"line":42,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":44,"column":3},"end":{"line":44,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":47,"column":1},"end":{"line":47,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":49,"column":3},"end":{"line":49,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":52,"column":1},"end":{"line":52,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":54,"column":3},"end":{"line":54,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":57,"column":1},"end":{"line":57,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":59,"column":3},"end":{"line":59,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":62,"column":1},"end":{"line":62,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":64,"column":3},"end":{"line":64,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":67,"column":1},"end":{"line":67,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":69,"column":3},"end":{"line":69,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":72,"column":1},"end":{"line":72,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":74,"column":3},"end":{"line":74,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":77,"column":1},"end":{"line":77,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":79,"column":3},"end":{"line":79,"column":7}}}]},{"locations":[{"message":"+1","range":{"start":{"line":82,"column":1},"end":{"line":82,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":84,"column":3},"end":{"line":84,"column":7}}}]}]}],"metrics":{"lines":88,"code_lines":85,"comment_lines":0}},{"path":"src/url_error_clean/program.go","language":"go","issues":[],"metrics":{"lines":56,"code_lines":53,"comment_lines":0}},{"path":"src/url_local_shadow_positive/program.go","language":"go","issues":[{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","range":{"start":{"line":7,"column":5},"end":{"line":7,"column":10}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":10,"column":1},"end":{"line":10,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":13,"column":1},"end":{"line":13,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":16,"column":1},"end":{"line":16,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":19,"column":1},"end":{"line":19,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":22,"column":1},"end":{"line":22,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":25,"column":1},"end":{"line":25,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":28,"column":1},"end":{"line":28,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":31,"column":1},"end":{"line":31,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":34,"column":1},"end":{"line":34,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":37,"column":1},"end":{"line":37,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":40,"column":1},"end":{"line":40,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":43,"column":1},"end":{"line":43,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":46,"column":1},"end":{"line":46,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":49,"column":1},"end":{"line":49,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":52,"column":1},"end":{"line":52,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":55,"column":1},"end":{"line":55,"column":3}}}]}]}],"metrics":{"lines":59,"code_lines":55,"comment_lines":0}},{"path":"src/url_nested_control_positive/program.go","language":"go","issues":[{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","range":{"start":{"line":5,"column":5},"end":{"line":5,"column":10}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":8,"column":2},"end":{"line":8,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":13,"column":2},"end":{"line":13,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":18,"column":2},"end":{"line":18,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":23,"column":2},"end":{"line":23,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":28,"column":2},"end":{"line":28,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":33,"column":2},"end":{"line":33,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":38,"column":2},"end":{"line":38,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":43,"column":2},"end":{"line":43,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":48,"column":2},"end":{"line":48,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":53,"column":2},"end":{"line":53,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":58,"column":2},"end":{"line":58,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":63,"column":2},"end":{"line":63,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":68,"column":2},"end":{"line":68,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":73,"column":2},"end":{"line":73,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":78,"column":2},"end":{"line":78,"column":4}}}]},{"locations":[{"message":"+1","range":{"start":{"line":83,"column":2},"end":{"line":83,"column":4}}}]}]}],"metrics":{"lines":88,"code_lines":85,"comment_lines":0}},{"path":"src/url_shadow_positive/program.go","language":"go","issues":[{"rule_key":"go:S3776","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","range":{"start":{"line":7,"column":5},"end":{"line":7,"column":10}},"flows":[{"locations":[{"message":"+1","range":{"start":{"line":9,"column":1},"end":{"line":9,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":12,"column":1},"end":{"line":12,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":15,"column":1},"end":{"line":15,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":18,"column":1},"end":{"line":18,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":21,"column":1},"end":{"line":21,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":24,"column":1},"end":{"line":24,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":27,"column":1},"end":{"line":27,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":30,"column":1},"end":{"line":30,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":33,"column":1},"end":{"line":33,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":36,"column":1},"end":{"line":36,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":39,"column":1},"end":{"line":39,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":42,"column":1},"end":{"line":42,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":45,"column":1},"end":{"line":45,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":48,"column":1},"end":{"line":48,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":51,"column":1},"end":{"line":51,"column":3}}}]},{"locations":[{"message":"+1","range":{"start":{"line":54,"column":1},"end":{"line":54,"column":3}}}]}]}],"metrics":{"lines":58,"code_lines":54,"comment_lines":0}}],"project":{"metrics":{"files":11,"lines":741,"code_lines":707,"comment_lines":0},"files":[{"path":"src/method_assertion_clean/program.go","classification":"source","status":"complete","metrics":{"lines":61,"code_lines":58,"comment_lines":0},"duplication":{"duplicated_lines":51,"duplicated_blocks":4,"duplicated_files":1,"duplicated_lines_density":83.60655737704919},"reason":null},{"path":"src/method_error_clean/program.go","classification":"source","status":"complete","metrics":{"lines":57,"code_lines":54,"comment_lines":0},"duplication":{"duplicated_lines":51,"duplicated_blocks":5,"duplicated_files":1,"duplicated_lines_density":89.47368421052632},"reason":null},{"path":"src/method_pointer_positive/program.go","classification":"source","status":"complete","metrics":{"lines":59,"code_lines":56,"comment_lines":0},"duplication":{"duplicated_lines":51,"duplicated_blocks":5,"duplicated_files":1,"duplicated_lines_density":86.4406779661017},"reason":null},{"path":"src/method_tuple_positive/program.go","classification":"source","status":"complete","metrics":{"lines":105,"code_lines":102,"comment_lines":0},"duplication":{"duplicated_lines":97,"duplicated_blocks":5,"duplicated_files":1,"duplicated_lines_density":92.38095238095238},"reason":null},{"path":"src/ordinary_error_clean/program.go","classification":"source","status":"complete","metrics":{"lines":55,"code_lines":53,"comment_lines":0},"duplication":{"duplicated_lines":50,"duplicated_blocks":3,"duplicated_files":1,"duplicated_lines_density":90.9090909090909},"reason":null},{"path":"src/selector_positive/program.go","classification":"source","status":"complete","metrics":{"lines":55,"code_lines":52,"comment_lines":0},"duplication":{"duplicated_lines":48,"duplicated_blocks":2,"duplicated_files":1,"duplicated_lines_density":87.27272727272727},"reason":null},{"path":"src/url_else_positive/program.go","classification":"source","status":"complete","metrics":{"lines":88,"code_lines":85,"comment_lines":0},"duplication":{"duplicated_lines":80,"duplicated_blocks":2,"duplicated_files":1,"duplicated_lines_density":90.9090909090909},"reason":null},{"path":"src/url_error_clean/program.go","classification":"source","status":"complete","metrics":{"lines":56,"code_lines":53,"comment_lines":0},"duplication":{"duplicated_lines":50,"duplicated_blocks":4,"duplicated_files":1,"duplicated_lines_density":89.28571428571429},"reason":null},{"path":"src/url_local_shadow_positive/program.go","classification":"source","status":"complete","metrics":{"lines":59,"code_lines":55,"comment_lines":0},"duplication":{"duplicated_lines":50,"duplicated_blocks":4,"duplicated_files":1,"duplicated_lines_density":84.7457627118644},"reason":null},{"path":"src/url_nested_control_positive/program.go","classification":"source","status":"complete","metrics":{"lines":88,"code_lines":85,"comment_lines":0},"duplication":{"duplicated_lines":80,"duplicated_blocks":2,"duplicated_files":1,"duplicated_lines_density":90.9090909090909},"reason":null},{"path":"src/url_shadow_positive/program.go","classification":"source","status":"complete","metrics":{"lines":58,"code_lines":54,"comment_lines":0},"duplication":{"duplicated_lines":50,"duplicated_blocks":3,"duplicated_files":1,"duplicated_lines_density":86.20689655172413},"reason":null}],"duplications":[{"language":"go","occurrences":[{"path":"src/method_assertion_clean/program.go","start_line":8,"end_line":58,"start_byte":169,"end_byte":981},{"path":"src/method_error_clean/program.go","start_line":6,"end_line":56,"start_byte":98,"end_byte":810},{"path":"src/method_pointer_positive/program.go","start_line":8,"end_line":58,"start_byte":160,"end_byte":872}]},{"language":"go","occurrences":[{"path":"src/method_assertion_clean/program.go","start_line":9,"end_line":58,"start_byte":191,"end_byte":981},{"path":"src/method_error_clean/program.go","start_line":7,"end_line":56,"start_byte":118,"end_byte":810},{"path":"src/method_pointer_positive/program.go","start_line":9,"end_line":58,"start_byte":180,"end_byte":872},{"path":"src/ordinary_error_clean/program.go","start_line":5,"end_line":54,"start_byte":81,"end_byte":773}]},{"language":"go","occurrences":[{"path":"src/method_assertion_clean/program.go","start_line":10,"end_line":58,"start_byte":197,"end_byte":981},{"path":"src/method_error_clean/program.go","start_line":8,"end_line":56,"start_byte":122,"end_byte":810},{"path":"src/method_pointer_positive/program.go","start_line":10,"end_line":58,"start_byte":184,"end_byte":872},{"path":"src/method_tuple_positive/program.go","start_line":56,"end_line":104,"start_byte":739,"end_byte":1427},{"path":"src/ordinary_error_clean/program.go","start_line":6,"end_line":54,"start_byte":85,"end_byte":773},{"path":"src/url_error_clean/program.go","start_line":7,"end_line":55,"start_byte":87,"end_byte":775},{"path":"src/url_local_shadow_positive/program.go","start_line":10,"end_line":58,"start_byte":176,"end_byte":864},{"path":"src/url_shadow_positive/program.go","start_line":9,"end_line":57,"start_byte":163,"end_byte":851}]},{"language":"go","occurrences":[{"path":"src/method_assertion_clean/program.go","start_line":11,"end_line":57,"start_byte":236,"end_byte":977},{"path":"src/method_error_clean/program.go","start_line":9,"end_line":55,"start_byte":159,"end_byte":808},{"path":"src/method_pointer_positive/program.go","start_line":11,"end_line":57,"start_byte":221,"end_byte":870},{"path":"src/method_tuple_positive/program.go","start_line":54,"end_line":100,"start_byte":733,"end_byte":1382},{"path":"src/method_tuple_positive/program.go","start_line":57,"end_line":103,"start_byte":776,"end_byte":1425},{"path":"src/ordinary_error_clean/program.go","start_line":7,"end_line":53,"start_byte":122,"end_byte":771},{"path":"src/url_error_clean/program.go","start_line":8,"end_line":54,"start_byte":124,"end_byte":773},{"path":"src/url_local_shadow_positive/program.go","start_line":11,"end_line":57,"start_byte":213,"end_byte":862},{"path":"src/url_shadow_positive/program.go","start_line":10,"end_line":56,"start_byte":200,"end_byte":849}]},{"language":"go","occurrences":[{"path":"src/method_error_clean/program.go","start_line":6,"end_line":56,"start_byte":96,"end_byte":810},{"path":"src/method_pointer_positive/program.go","start_line":8,"end_line":58,"start_byte":158,"end_byte":872}]},{"language":"go","occurrences":[{"path":"src/method_tuple_positive/program.go","start_line":8,"end_line":53,"start_byte":147,"end_byte":704},{"path":"src/method_tuple_positive/program.go","start_line":11,"end_line":56,"start_byte":184,"end_byte":741}]},{"language":"go","occurrences":[{"path":"src/selector_positive/program.go","start_line":6,"end_line":50,"start_byte":69,"end_byte":652},{"path":"src/selector_positive/program.go","start_line":9,"end_line":53,"start_byte":108,"end_byte":691}]},{"language":"go","occurrences":[{"path":"src/url_else_positive/program.go","start_line":7,"end_line":81,"start_byte":83,"end_byte":1071},{"path":"src/url_else_positive/program.go","start_line":12,"end_line":86,"start_byte":149,"end_byte":1137}]},{"language":"go","occurrences":[{"path":"src/url_error_clean/program.go","start_line":6,"end_line":55,"start_byte":49,"end_byte":775},{"path":"src/url_local_shadow_positive/program.go","start_line":9,"end_line":58,"start_byte":138,"end_byte":864}]},{"language":"go","occurrences":[{"path":"src/url_error_clean/program.go","start_line":6,"end_line":55,"start_byte":66,"end_byte":775},{"path":"src/url_local_shadow_positive/program.go","start_line":9,"end_line":58,"start_byte":155,"end_byte":864},{"path":"src/url_shadow_positive/program.go","start_line":8,"end_line":57,"start_byte":142,"end_byte":851}]},{"language":"go","occurrences":[{"path":"src/url_nested_control_positive/program.go","start_line":7,"end_line":81,"start_byte":92,"end_byte":990},{"path":"src/url_nested_control_positive/program.go","start_line":12,"end_line":86,"start_byte":152,"end_byte":1050}]}],"duplication":{"duplicated_lines":658,"duplicated_blocks":39,"duplicated_files":11,"duplicated_lines_density":88.79892037786774},"complete":true,"warnings":[],"roots":["src"]}}"#;

const FILE_LOCAL_GENERIC: &str = r#"{"issues":[{"primaryLocation":{"filePath":"src/method_pointer_positive/program.go","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","textRange":{"endColumn":10,"endLine":8,"startColumn":5,"startLine":8}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":10,"startColumn":1,"startLine":10}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":13,"startColumn":1,"startLine":13}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":16,"startColumn":1,"startLine":16}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":19,"startColumn":1,"startLine":19}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":22,"startColumn":1,"startLine":22}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":25,"startColumn":1,"startLine":25}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":28,"startColumn":1,"startLine":28}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":31,"startColumn":1,"startLine":31}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":34,"startColumn":1,"startLine":34}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":37,"startColumn":1,"startLine":37}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":40,"startColumn":1,"startLine":40}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":43,"startColumn":1,"startLine":43}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":46,"startColumn":1,"startLine":46}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":49,"startColumn":1,"startLine":49}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":52,"startColumn":1,"startLine":52}},{"filePath":"src/method_pointer_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":55,"startColumn":1,"startLine":55}}]},{"primaryLocation":{"filePath":"src/method_tuple_positive/program.go","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","textRange":{"endColumn":10,"endLine":6,"startColumn":5,"startLine":6}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":56,"startColumn":1,"startLine":56}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":59,"startColumn":1,"startLine":59}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":62,"startColumn":1,"startLine":62}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":65,"startColumn":1,"startLine":65}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":68,"startColumn":1,"startLine":68}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":71,"startColumn":1,"startLine":71}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":74,"startColumn":1,"startLine":74}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":77,"startColumn":1,"startLine":77}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":80,"startColumn":1,"startLine":80}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":83,"startColumn":1,"startLine":83}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":86,"startColumn":1,"startLine":86}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":89,"startColumn":1,"startLine":89}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":92,"startColumn":1,"startLine":92}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":95,"startColumn":1,"startLine":95}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":98,"startColumn":1,"startLine":98}},{"filePath":"src/method_tuple_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":101,"startColumn":1,"startLine":101}}]},{"primaryLocation":{"filePath":"src/selector_positive/program.go","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","textRange":{"endColumn":10,"endLine":5,"startColumn":5,"startLine":5}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":6,"startColumn":1,"startLine":6}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":9,"startColumn":1,"startLine":9}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":12,"startColumn":1,"startLine":12}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":15,"startColumn":1,"startLine":15}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":18,"startColumn":1,"startLine":18}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":21,"startColumn":1,"startLine":21}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":24,"startColumn":1,"startLine":24}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":27,"startColumn":1,"startLine":27}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":30,"startColumn":1,"startLine":30}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":33,"startColumn":1,"startLine":33}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":36,"startColumn":1,"startLine":36}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":39,"startColumn":1,"startLine":39}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":42,"startColumn":1,"startLine":42}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":45,"startColumn":1,"startLine":45}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":48,"startColumn":1,"startLine":48}},{"filePath":"src/selector_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":51,"startColumn":1,"startLine":51}}]},{"primaryLocation":{"filePath":"src/url_else_positive/program.go","message":"Refactor this method to reduce its Cognitive Complexity from 32 to the 15 allowed.","textRange":{"endColumn":10,"endLine":5,"startColumn":5,"startLine":5}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":7,"startColumn":1,"startLine":7}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":9,"startColumn":3,"startLine":9}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":12,"startColumn":1,"startLine":12}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":14,"startColumn":3,"startLine":14}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":17,"startColumn":1,"startLine":17}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":19,"startColumn":3,"startLine":19}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":22,"startColumn":1,"startLine":22}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":24,"startColumn":3,"startLine":24}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":27,"startColumn":1,"startLine":27}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":29,"startColumn":3,"startLine":29}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":32,"startColumn":1,"startLine":32}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":34,"startColumn":3,"startLine":34}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":37,"startColumn":1,"startLine":37}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":39,"startColumn":3,"startLine":39}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":42,"startColumn":1,"startLine":42}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":44,"startColumn":3,"startLine":44}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":47,"startColumn":1,"startLine":47}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":49,"startColumn":3,"startLine":49}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":52,"startColumn":1,"startLine":52}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":54,"startColumn":3,"startLine":54}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":57,"startColumn":1,"startLine":57}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":59,"startColumn":3,"startLine":59}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":62,"startColumn":1,"startLine":62}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":64,"startColumn":3,"startLine":64}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":67,"startColumn":1,"startLine":67}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":69,"startColumn":3,"startLine":69}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":72,"startColumn":1,"startLine":72}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":74,"startColumn":3,"startLine":74}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":77,"startColumn":1,"startLine":77}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":79,"startColumn":3,"startLine":79}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":82,"startColumn":1,"startLine":82}},{"filePath":"src/url_else_positive/program.go","message":"+1","textRange":{"endColumn":7,"endLine":84,"startColumn":3,"startLine":84}}]},{"primaryLocation":{"filePath":"src/url_local_shadow_positive/program.go","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","textRange":{"endColumn":10,"endLine":7,"startColumn":5,"startLine":7}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":10,"startColumn":1,"startLine":10}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":13,"startColumn":1,"startLine":13}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":16,"startColumn":1,"startLine":16}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":19,"startColumn":1,"startLine":19}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":22,"startColumn":1,"startLine":22}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":25,"startColumn":1,"startLine":25}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":28,"startColumn":1,"startLine":28}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":31,"startColumn":1,"startLine":31}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":34,"startColumn":1,"startLine":34}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":37,"startColumn":1,"startLine":37}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":40,"startColumn":1,"startLine":40}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":43,"startColumn":1,"startLine":43}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":46,"startColumn":1,"startLine":46}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":49,"startColumn":1,"startLine":49}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":52,"startColumn":1,"startLine":52}},{"filePath":"src/url_local_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":55,"startColumn":1,"startLine":55}}]},{"primaryLocation":{"filePath":"src/url_nested_control_positive/program.go","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","textRange":{"endColumn":10,"endLine":5,"startColumn":5,"startLine":5}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":8,"startColumn":2,"startLine":8}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":13,"startColumn":2,"startLine":13}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":18,"startColumn":2,"startLine":18}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":23,"startColumn":2,"startLine":23}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":28,"startColumn":2,"startLine":28}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":33,"startColumn":2,"startLine":33}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":38,"startColumn":2,"startLine":38}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":43,"startColumn":2,"startLine":43}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":48,"startColumn":2,"startLine":48}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":53,"startColumn":2,"startLine":53}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":58,"startColumn":2,"startLine":58}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":63,"startColumn":2,"startLine":63}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":68,"startColumn":2,"startLine":68}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":73,"startColumn":2,"startLine":73}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":78,"startColumn":2,"startLine":78}},{"filePath":"src/url_nested_control_positive/program.go","message":"+1","textRange":{"endColumn":4,"endLine":83,"startColumn":2,"startLine":83}}]},{"primaryLocation":{"filePath":"src/url_shadow_positive/program.go","message":"Refactor this method to reduce its Cognitive Complexity from 16 to the 15 allowed.","textRange":{"endColumn":10,"endLine":7,"startColumn":5,"startLine":7}},"ruleId":"go:S3776","secondaryLocations":[{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":9,"startColumn":1,"startLine":9}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":12,"startColumn":1,"startLine":12}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":15,"startColumn":1,"startLine":15}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":18,"startColumn":1,"startLine":18}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":21,"startColumn":1,"startLine":21}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":24,"startColumn":1,"startLine":24}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":27,"startColumn":1,"startLine":27}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":30,"startColumn":1,"startLine":30}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":33,"startColumn":1,"startLine":33}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":36,"startColumn":1,"startLine":36}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":39,"startColumn":1,"startLine":39}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":42,"startColumn":1,"startLine":42}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":45,"startColumn":1,"startLine":45}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":48,"startColumn":1,"startLine":48}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":51,"startColumn":1,"startLine":51}},{"filePath":"src/url_shadow_positive/program.go","message":"+1","textRange":{"endColumn":3,"endLine":54,"startColumn":1,"startLine":54}}]}],"rules":[{"cleanCodeAttribute":"FOCUSED","description":"Hoonarqube finding for `go:S3776`.","engineId":"hoonarqube","id":"go:S3776","impacts":[{"severity":"HIGH","softwareQuality":"MAINTAINABILITY"}],"name":"go:S3776","severity":"CRITICAL","type":"CODE_SMELL"}]}"#;
