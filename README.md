Gosanitize is a whitelist-based HTML sanitizer. Given a list of acceptable elements and attributes, Sanitize will remove all unacceptable HTML from a string.

inspired by https://github.com/mjibson/goread/tree/master/sanitizer
found a better impl: https://github.com/microcosm-cc/bluemonday


## usage

``` Go
import "gosanitize"

// sanitize html by whitelist
sanitizer := gosanitize.NewDefault()
sanitizer.Sanitize("...") is the same as:
gosanitize.Sanitize("...")

// here are the defaults:
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

// Based on list from Wikipedia's URI scheme
// http://en.wikipedia.org/wiki/URI_scheme
var acceptableUriSchemes = []string{ "aim", "apt", "bitcoin", "callto", "cvs", "facetime", "feed", "ftp", "git", "gopher", "gtalk", "http", "https", "imap", "irc", "itms", "jabber", "magnet", "mailto", "mms", "msnim", "news", "nntp", "rtmp", "rtsp", "sftp", "skype", "svn", "ymsgr" }
//

//
// strip html
sanitizer := gosanitize.NewStrip()
html := `some <tag> html </tag> ... text`
sanitizer.Sanitize(html)

// custom setting
sanitizer := gosanitize.New()
sanitizer.Attributes =
sanitizer.Attributes =
sanitizer.StripHtml =
sanitizer.EnsureInPairs =
sanitizer.ForceHrefLink =
sanitizer.ForceTargetBlank =
sanitizer.ForceRelNofollow =
sanitizer.URISchemes =

// example:
sanitizer.Elements = []string{"a", "bold", "div", "ul", "li", "u", "i", "p"}
sanitizer.Attributes = []string{"href", "target", "rel", "title"}
html := `some <tag> html </tag> ... text`
html_sanitized, err := sanitizer.Sanitize(html)

```

## test

```
go test
```

## License
MIT
