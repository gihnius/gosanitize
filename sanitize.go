/*

Gosanitize is a whitelist-based HTML sanitizer. Given a list of acceptable
elements and attributes, Sanitize will remove all unacceptable HTML from a
string.

inspired by https://github.com/mjibson/goread/tree/master/sanitizer

import "gosanitize"

// default
gosanitize.Sanitize("...")

// sanitize html by whitelist
sanitizer := gosanitize.NewDefault()
sanitizer.Elements = []string{"a", "bold", "div", "ul", "li", "u", "i", "p"}
sanitizer.Attributes = []string{"href", "target", "rel", "title"}
html := `some <tag> html </tag> ... text`
html_sanitized, err := sanitizer.Sanitize(html)

// strip html
sanitizer := gosanitize.NewStrip()
html := `some <tag> html </tag> ... text`
sanitizer.Sanitize(html)

// custom setting
sanitizer := gosanitize.New()
sanitizer.Elements = []
sanitizer.Attributes = []
sanitizer.StripHtml = true/false
sanitizer.EnsureInPairs = true/false
sanitizer.ForceHrefLink = true/false
sanitizer.ForceTargetBlank = true/false
sanitizer.ForceRelNofollow = true/false
sanitizer.URISchemes = []

sanitizer.Sanitize("...")

*/

package gosanitize

import (
    "bytes"
    "code.google.com/p/go.net/html"
    "errors"
    "io"
    "net/url"
    "strings"
    "unicode/utf8"
)

type sanitizer struct {
    // acceptable tag elements
    Elements []string
    elementsMap map[string]bool
    // acceptable attributes
    Attributes []string
    attributesMap map[string]bool

    // not Elements whitelist, remove all tags
    StripHtml bool

    // start tags count not equals to end tags count
    // why has this?
    // the pkg of code.google.com/p/go.net/html "fail" to parse input like the following:
    // <<p> dsfd </p> => &lt;&ltp&gt; dsfd </p>
    // <h1> dlsfjads f<</h1>> => ...
    // So will leave over a start or end tag without end or start tag.
    EnsureInPairs bool

    // for <a> tag force target or rel attributes for non internal links
    // where internal links means that urls begin with a slash '/'
    ForceTargetBlank bool
    ForceRelNofollow bool

    // prevent href to be empty
    ForceHrefLink bool

    // acceptable URI schemes
    URISchemes []string
    uriSchemesMap map[string]bool
}

// default allow these tags
var acceptableTagsList = []string{
    "h1", "h2", "h3", "h4", "h5", "h6",
    "p", "hr", "pre", "blockquote", "div", "a", "code", "br", "img",
    "ol", "ul", "li",
    "em", "strong", "small", "strike", "i", "b", "u",
    "table", "caption", "colgroup", "col", "tbody", "thead", "tfoot", "tr", "td", "th",
}

// default allow attributes
var acceptableAttributesList = []string{
    "valign", "align",
    "rows", "cols", "colspan", "cellpadding", "cellspacing", "rowspan",
    "title", "href", "alt", "rel", "target", "src",
    "selected","checked",
}

// always remove these tags
var unacceptableTags = []string{ "script", "applet", "style" }
var unacceptableTagsMap map[string]bool

// Based on list from Wikipedia's URI scheme
// http://en.wikipedia.org/wiki/URI_scheme
var acceptableUriSchemes = []string{ "aim", "apt", "bitcoin", "callto", "cvs", "facetime", "feed", "ftp", "git", "gopher", "gtalk", "http", "https", "imap", "irc", "itms", "jabber", "magnet", "mailto", "mms", "msnim", "news", "nntp", "rtmp", "rtsp", "sftp", "skype", "svn", "ymsgr" }

// while the "code.google.com/p/go.net/html" pkg treat pattern '<XX/>' as SelfClosingTagToken
// will ignore for start tag when source is html5 which there is not a slash '/' in tag
var html5SelfClosingTags = []string {"br", "img", "hr", "area", "base", "col", "command", "embed", "input", "keygen", "link", "meta", "param", "source", "track", "wbr"}
var html5SelfClosingTagsMap map[string]bool

// default create an empty instance
func New() *sanitizer {
    s := &sanitizer{}
    return s
}

// create an instance to strip html only
func NewStrip() *sanitizer {
    s := New()
    s.StripHtml = true
    return s
}

// create an instance to apply default elements/attributes/schemes
func NewDefault() *sanitizer {
    s := New()
    s.StripHtml = false
    s.Elements = acceptableTagsList
    s.Attributes = acceptableAttributesList
    s.URISchemes = acceptableUriSchemes
    s.StrictMode()
    return s
}

func (s *sanitizer) StrictMode() {
    s.EnsureInPairs = true
    s.ForceHrefLink = true
    s.ForceTargetBlank = true
    s.ForceRelNofollow = true
}

// setting up before sanitizing
func (s *sanitizer) setting() {
    if len(s.Elements) > 0 {
        s.StripHtml = false
    }
    s.attributesMap = slice2map(s.Attributes)
    s.elementsMap = slice2map(s.Elements)
    s.uriSchemesMap = slice2map(s.URISchemes)

    html5SelfClosingTagsMap = slice2map(html5SelfClosingTags)
    unacceptableTagsMap = slice2map(unacceptableTags)
}

func slice2map(list []string) map[string]bool {
    var rt = make(map[string]bool)
    for _, l := range list {
        rt[l] = true
    }
    return rt
}

// if a "url" without scheme, prepend 'http://'
func (s *sanitizer) forceHttpScheme(l string) string {
    for _, sch := range s.URISchemes {
        if strings.HasPrefix(l, sch) {
            return l
        }
    }
    return "http://" + l
}

// return a link with acceptable scheme
func (s *sanitizer) sanitizeLink(l string) string {
    var p *url.URL
    var err error
    if strings.TrimSpace(l) == "" {
        return ""
    }
    if isInternalLink(l) {
        return l
    }
    if s.ForceHrefLink {
        return s.forceHttpScheme(l)
    }
    p, err = url.Parse(l)
    if err != nil {
        return ""
    }
    if s.uriSchemesMap[p.Scheme] {
        return ""
    }
    return p.String()
}

// that partial url is begin with '/' or '#' but not '//'
func isInternalLink(url string) (yes bool) {
    link := []byte(url)
    yes = false
    // a tag begin with '#'
    if len(link) > 0 && link[0] == '#' {
        yes = true
    }
    // link begin with '/' but not '//', the second maybe a protocol relative link
    if len(link) >= 2 && link[0] == '/' && link[1] != '/' {
        yes = true
    }
    // only the root '/'
    if len(link) == 1 && link[0] == '/' {
        yes = true
    }
    return
}

// sanitize attributes in place
func (s *sanitizer) sanitizeAttributes(t *html.Token) {
    var attrs []html.Attribute
    var is_link = false
    var is_internal_link = false
    var no_target = true
    var no_rel = true

    for _, a := range t.Attr {
        if s.attributesMap[a.Key] {
            if a.Key == "href" || a.Key == "src" {
                a.Val = s.sanitizeLink(a.Val)
            }
            if a.Key == "href" {
                is_link = true
                is_internal_link = isInternalLink(a.Val)
            }
            // modify if exist
            if a.Key == "target" && !is_internal_link && s.ForceTargetBlank {
                no_target = false
                a.Val = "_blank"
            }
            if a.Key == "rel" && !is_internal_link && s.ForceRelNofollow {
                no_rel = false
                a.Val = "nofollow"
            }
            // collect acceptable
            attrs = append(attrs, a)
        }
    }
    // append if not exist
    if is_link && !is_internal_link {
        if no_rel && s.ForceRelNofollow {
            attrs = append(attrs, html.Attribute{ Key: "rel", Val: "nofollow"})
        }
        if no_target && s.ForceTargetBlank {
            attrs = append(attrs, html.Attribute{ Key: "target", Val: "_blank"})
        }
    }

    t.Attr = attrs
}

// sanitize html. make sure the input is UTF-8 encoding
func (s *sanitizer) Sanitize(str string) (string, error) {
    if !utf8.ValidString(str) {
        return "", errors.New("Invalid UTF-8 encoding string!")
    }
    s.setting()
    r := bytes.NewReader([]byte(strings.TrimSpace(str)))
    z := html.NewTokenizer(r)
    buf := &bytes.Buffer{}
    strip := &bytes.Buffer{}
    skip := 0
    startTags := 0
    endTags := 0

    for {
        if z.Next() == html.ErrorToken {
            err := z.Err()
            if err == io.EOF {
                break
            } else {
                return str, err
            }
        }
        t := z.Token()
        if t.Type == html.StartTagToken || t.Type == html.SelfClosingTagToken {
            if t.Type == html.StartTagToken {
                if !html5SelfClosingTagsMap[t.Data]{
                    startTags += 1
                }
            }
            if !s.elementsMap[t.Data] {
                if unacceptableTagsMap[t.Data] && t.Type != html.SelfClosingTagToken {
                    skip += 1
                }
            } else {
                s.sanitizeAttributes(&t)
                buf.WriteString(t.String())
            }
        } else if t.Type == html.EndTagToken {
            endTags += 1
            if !s.elementsMap[t.Data] {
                if unacceptableTagsMap[t.Data] {
                    skip -= 1
                }
            } else {
                buf.WriteString(t.String())
            }
        } else if skip == 0 {
            buf.WriteString(t.String())
            if t.Type == html.TextToken && s.StripHtml {
                strip.WriteString(t.String())
            }
        }
    }

    if s.EnsureInPairs && (startTags != endTags) {
        return "", errors.New("Tags pairs mismatch!")
    }
    // no tags whitelist, return stripped text
    if s.StripHtml {
        return strip.String(), nil
    }
    return buf.String(), nil
}

// apply default whitelist
func Sanitize(str string) (string, error) {
    s := NewDefault()
    return s.Sanitize(str)
}
