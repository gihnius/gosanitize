
Gosanitize is a whitelist-based HTML sanitizer. Given a list of acceptable
elements and attributes, Sanitize will remove all unacceptable HTML from a
string.

inspired by https://github.com/mjibson/goread/tree/master/sanitizer

``` Go
import "gosanitize"

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
sanitizer.Attributes =
sanitizer.Attributes =
sanitizer.StripHtml =
sanitizer.EnsureInPairs =
sanitizer.ForceHrefLink =
sanitizer.ForceTargetBlank =
sanitizer.ForceRelNofollow =
sanitizer.URISchemes =

sanitizer.Sanitize("...")

```
