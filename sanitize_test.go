package gosanitize

import (
	"fmt"
	"testing"
)

// element 0 is actual, element 1 is expected
type T [2]string

func run_sanitize_tests(t *testing.T, tt []T, s *sanitizer) {
	for _, in := range tt {
		input := in[0]
		expected := in[1]
		actual, err := s.Sanitize(input)
		if err != nil {
			fmt.Println("==== Test: with error: ", err, " ====")
			fmt.Printf("Input:[%#v]-Expected:[%#v]-Actual:[%#v]\n", input, expected, actual)
		}
		if actual != expected {
			t.Errorf("\nInput:[%#v]\nExpected:[%#v]\nActual:[%#v]\n", input, expected, actual)
		}
	}
}

func Test_Sanitize_StripTags(t *testing.T) {
	tt := []T{
		T{
			"<html>html document</html>",
			"html document",
		},
		T{
			`a link: <a href="http://example.com/">example.com</a>`,
			`a link: example.com`,
		},
		T{
			`<script>alert(1);</script>`,
			``,
		},
		T{
			`<meta name="abc" value="123">`,
			``,
		},
		T{
			`<span style="font-size:100">font</span>`,
			`font`,
		},
		T{
			`<a href="//abc.com"><b>abc.com</b></a><span> a Good site</span>`,
			`abc.com a Good site`,
		},
		T{
			`<<p>paragraphs</p>`,
			`&lt;&lt;p&gt;paragraphs`,
		},
	}
	s := NewStrip()
	run_sanitize_tests(t, tt, s)
}

func Test_Sanitize_DefaultList(t *testing.T) {
	tt := []T{
		T{
			"<html>html document</html>",
			"html document",
		},
		T{
			`a link: <a href="http://example.com/">example.com</a>`,
			`a link: <a href="http://example.com/" rel="nofollow" target="_blank">example.com</a>`,
		},
		T{
			`<script>alert(1);</script>`,
			``,
		},
		T{
			`<meta name="abc" value="123">`,
			``,
		},
		T{
			`<span style="font-size:100">font</span>`,
			`font`,
		},
		T{
			`<pre>Pre</pre>`,
			`<pre>Pre</pre>`,
		},
		T{
			`<this>Ignore This Tag</this>`,
			`Ignore This Tag`,
		},
		T{
			`<iframe>Not allow by default</iframe>`,
			`Not allow by default`,
		},
		T{
			`<p>default p</p>`,
			`<p>default p</p>`,
		},
		T{
			`<a href="/abc">123</a>`,
			`<a href="/abc">123</a>`,
		},
		T{
			`<a href="/abc" noattr="ignore">123</a>`,
			`<a href="/abc">123</a>`,
		},
		T{ // use ForceTargetBlank = true to correct attr to _blank
			`<a href="/abc" target="default">123</a>`,
			`<a href="/abc" target="default">123</a>`,
		},
		T{ // use ForceHrefLink = true to prevent href to be empty
			`<a href="javascript:alert(1);">javascript</a>`,
			`<a href="http://javascript:alert(1);" rel="nofollow" target="_blank">javascript</a>`,
		},
	}
	s := NewDefault()
	run_sanitize_tests(t, tt, s)
}

func Test_Sanitize_TagsList(t *testing.T) {
	tt := []T{
		T{
			"<html>html document</html>",
			"html document",
		},
		T{
			`<h1>not support heading</h1>`,
			`not support heading`,
		},
		T{
			`<pre>Pre</pre>`,
			`<pre>Pre</pre>`,
		},
		T{
			`<this>Ignore This Tag</this>`,
			`Ignore This Tag`,
		},
		T{
			`<iframe>Not allow by default</iframe>`,
			`Not allow by default`,
		},
		T{
			`<p class="no this attr">attr disallow</p>`,
			`<p>attr disallow</p>`,
		},
		T{
			`<img src="abc">`,
			`<img src="http://abc">`,
		},
		T{
			`<img src="abc" alt="not allow">`,
			`<img src="http://abc">`,
		},
		T{ // escape attr
			`<img src="<wtf>">`,
			`<img src="http://&lt;wtf&gt;">`,
		},
		T{ // escape text
			`<a href="/abc"><>&$#!!#+><|</a>`,
			`<a href="/abc">&lt;&gt;&amp;$#!!#+&gt;&lt;|</a>`,
		},
		T{
			`<a href="/abc" noattr="ignore">123</a>`,
			`<a href="/abc">123</a>`,
		},
		T{ // use ForceTargetBlank but it's internal link
			`<a href="/abc" target="default">123</a>`,
			`<a href="/abc">123</a>`,
		},
		T{ // use ForceTargetBlank and ForceHrefLink
			`<a href="abc.com" target="default">123</a>`,
			`<a href="http://abc.com" rel="nofollow" target="_blank">123</a>`,
		},
		T{ // use ForceHrefLink = true
			`<a href="javascript:alert(1);">javascript</a>`,
			`<a href="http://javascript:alert(1);" rel="nofollow" target="_blank">javascript</a>`,
		},
		T{ // force target/rel,
			`a link: <a href="http://example.com/">example.com</a>`,
			`a link: <a href="http://example.com/" rel="nofollow" target="_blank">example.com</a>`,
		},
	}

	s := New()
	s.Elements = []string{"a", "br", "p", "pre", "img"}
	s.Attributes = []string{"href", "src"}
	s.URISchemes = []string{"http", "https", "ftp"}
	s.StrictMode()
	run_sanitize_tests(t, tt, s)
}

func Test_Sanitize_TagsPairs(t *testing.T) {
	tt := []T{
		T{ // the html pkg not take here as a correct start tag
			`<<p>Why SO?</p>`,
			`&lt;&lt;p&gt;Why SO?</p>`,
		},
		T{ // all escape here
			`<<<<<<pre>Why Why<<<</pre>`,
			`&lt;&lt;&lt;&lt;&lt;&lt;pre&gt;Why Why&lt;&lt;&lt;&lt;/pre&gt;`,
		},
		T{ // why here is ok
			`<pre>so what</pre>>>>>>`,
			`<pre>so what</pre>&gt;&gt;&gt;&gt;&gt;`,
		},
	}
	s := New()
	s.Elements = []string{"a", "br", "p", "pre", "img"}
	s.Attributes = []string{"href", "src"}
	s.EnsureInPairs = false
	run_sanitize_tests(t, tt, s)
}
