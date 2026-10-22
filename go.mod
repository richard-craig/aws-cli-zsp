module github.com/richard-craig/aws-cli-zsp

go 1.24.0

require golang.org/x/sys v0.37.0

// Vendored copy of the Go team's x/sys v0.37.0 (BSD-3-Clause), windows/ subtree
// only, so the build needs no network and the dependency is auditable in-repo.
replace golang.org/x/sys => ./third_party/x-sys
