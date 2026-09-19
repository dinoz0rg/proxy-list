package checker_test

import (
	"strings"
	"testing"

	"proxies-checker/internal/checker"
)

func TestBodyHasManualSuccessMarker(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want bool
	}{
		{"plain double quotes", `<html><head><meta name="application-name" content="JetBrains"></head></html>`, true},
		{"self-closing", `<html><head><meta name="application-name" content="JetBrains"/></head></html>`, true},
		{"self-closing with space", `<meta name="application-name" content="JetBrains" />`, true},
		{"single quotes", `<meta name='application-name' content='JetBrains'>`, true},
		{"unquoted", `<meta name=application-name content=JetBrains>`, true},
		{"attribute order swapped", `<meta content="JetBrains" name="application-name">`, true},
		{"whitespace and newlines", "<meta\n\tname = \"application-name\"\n\n   content =\t\"JetBrains\"\n/>", true},
		{"extra attributes", `<meta data-x="1" name="application-name" id="app" content="JetBrains" lang="en">`, true},
		{"uppercase tag and attributes", `<META NAME="application-name" CONTENT="JetBrains">`, true},
		{"value whitespace trimmed", `<meta name=" application-name " content=" JetBrains ">`, true},
		{"deep in a real page", `<!DOCTYPE html><html lang="en"><head><title>x</title><link rel="icon" href="/f.ico"><meta charset="utf-8"><meta name="application-name" content="JetBrains"/><script>var a=1;</script></head><body></body></html>`, true},

		{"empty body", ``, false},
		{"plain text", `JetBrains application-name`, false},
		{"no meta", `<html><head><title>JetBrains</title></head></html>`, false},
		{"other meta only", `<meta name="description" content="JetBrains">`, false},
		{"inside comment", `<html><head><!-- <meta name="application-name" content="JetBrains"> --></head></html>`, false},
		{"inside script", `<script>document.write('<meta name="application-name" content="JetBrains">');</script>`, false},
		{"inside style", `<style>/* <meta name="application-name" content="JetBrains"> */</style>`, false},
		{"escaped text", `<p>&lt;meta name="application-name" content="JetBrains"&gt;</p>`, false},
		{"wrong content", `<meta name="application-name" content="JetBrains Space">`, false},
		{"wrong name", `<meta name="application-nam" content="JetBrains">`, false},
		{"lowercase content value", `<meta name="application-name" content="jetbrains">`, false},
		{"missing content attr", `<meta name="application-name">`, false},
		{"attrs on different tags", `<meta name="application-name"><meta content="JetBrains">`, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := checker.BodyHasManualSuccessMarker(strings.NewReader(tc.body)); got != tc.want {
				t.Fatalf("BodyHasManualSuccessMarker(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}
