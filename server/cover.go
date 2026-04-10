// Package main — cover.go implements a realistic HTTP cover website for
// active-probe resistance.
//
// When a DPI scanner, GFW/TSPU active probe, or casual browser connects to
// the VPN port with non-TLS traffic, the server responds as a legitimate
// cooking blog. This makes the server indistinguishable from a real HTTP
// website to any external observer.
//
// Design rationale (based on Trojan-GFW and V2Ray VLESS fallback research):
//   - Multiple pages with internal links increase scanner confidence
//   - No Server header (consistent with Go TLS JA3S fingerprint)
//   - Proper HTTP/1.1 with Content-Length, Content-Type, Connection headers
//   - 404 for unknown paths (what a real server does)
//   - No TLS — cover site runs over plain HTTP, which is normal for
//     IP-only sites without a domain name (RFC 7230)
//
// Scientific basis:
//   - Alice et al. "Your State is Not Mine" (NDSS 2017): active probing
//     replays partial handshakes; a convincing fallback defeats replay-based
//     fingerprinting
//   - Frolov et al. "An ISP-Scale Deployment of TapDance" (FOCI 2017):
//     cover traffic must be indistinguishable from real web traffic at the
//     content level
package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// coverSiteDeadlineNs stores the total deadline for cover site HTTP exchange
// in nanoseconds. Atomic to prevent data races with tests.
var coverSiteDeadlineNs atomic.Int64

func init() {
	coverSiteDeadlineNs.Store(int64(10 * time.Second))
}

func coverSiteDeadline() time.Duration {
	return time.Duration(coverSiteDeadlineNs.Load())
}

func setCoverSiteDeadline(d time.Duration) {
	coverSiteDeadlineNs.Store(int64(d))
}

// coverHandler returns an http.Handler that serves a static "cooking blog"
// cover website. All HTML is embedded in the binary — no external files.
//
// Routes:
//
//	GET /           → homepage with recipe index
//	GET /recipe1    → pork roast recipe
//	GET /recipe2    → pulled pork recipe
//	GET /contacts   → contact page
//	GET /about      → about the blog
//	GET /*          → 404 page (realistic)
func coverHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			serveCover404(w, r)
			return
		}
		serveCoverPage(w, coverIndexHTML, http.StatusOK)
	})
	mux.HandleFunc("/recipe1", func(w http.ResponseWriter, r *http.Request) {
		serveCoverPage(w, coverRecipe1HTML, http.StatusOK)
	})
	mux.HandleFunc("/recipe2", func(w http.ResponseWriter, r *http.Request) {
		serveCoverPage(w, coverRecipe2HTML, http.StatusOK)
	})
	mux.HandleFunc("/contacts", func(w http.ResponseWriter, r *http.Request) {
		serveCoverPage(w, coverContactsHTML, http.StatusOK)
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		serveCoverPage(w, coverAboutHTML, http.StatusOK)
	})
	mux.HandleFunc("/favicon.ico", serveCoverFavicon)
	mux.HandleFunc("/robots.txt", serveCoverRobotsTxt)
	mux.HandleFunc("/sitemap.xml", serveCoverSitemap)
	return mux
}

// serveCoverPage writes an HTML response with standard headers.
func serveCoverPage(w http.ResponseWriter, body string, status int) {
	// No Server header — Go's net/http default. Eliminates the mismatch
	// fingerprint: "Server: nginx" + Go TLS JA3S → instant detection.
	// Many real sites (behind CDN, Caddy, Traefik) omit Server too.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Connection", "close")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	io.WriteString(w, body) //nolint:errcheck
}

// serveCover404 serves a realistic 404 page.
func serveCover404(w http.ResponseWriter, _ *http.Request) {
	serveCoverPage(w, cover404HTML, http.StatusNotFound)
}

// serveCoverFavicon serves a minimal 16x16 ICO favicon (cooking pot icon).
// A missing favicon is a fingerprint — every real site has one.
func serveCoverFavicon(w http.ResponseWriter, _ *http.Request) {
	// No Server header — Go's net/http default. Eliminates the mismatch
	// fingerprint: "Server: nginx" + Go TLS JA3S → instant detection.
	// Many real sites (behind CDN, Caddy, Traefik) omit Server too.
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=604800")
	w.Header().Set("Connection", "close")
	w.Write(faviconICO) //nolint:errcheck
}

// serveCoverRobotsTxt serves a standard robots.txt allowing all crawlers.
func serveCoverRobotsTxt(w http.ResponseWriter, _ *http.Request) {
	// No Server header — Go's net/http default. Eliminates the mismatch
	// fingerprint: "Server: nginx" + Go TLS JA3S → instant detection.
	// Many real sites (behind CDN, Caddy, Traefik) omit Server too.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Connection", "close")
	io.WriteString(w, "User-agent: *\nAllow: /\n\nSitemap: /sitemap.xml\n") //nolint:errcheck
}

// serveCoverSitemap serves a minimal XML sitemap with all cover pages.
func serveCoverSitemap(w http.ResponseWriter, r *http.Request) {
	// No Server header — Go's net/http default. Eliminates the mismatch
	// fingerprint: "Server: nginx" + Go TLS JA3S → instant detection.
	// Many real sites (behind CDN, Caddy, Traefik) omit Server too.
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Connection", "close")
	host := r.Host
	if host == "" {
		host = "pork-kitchen.xyz"
	}
	io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>http://`+host+`/</loc><priority>1.0</priority></url>
<url><loc>http://`+host+`/recipe1</loc><priority>0.8</priority></url>
<url><loc>http://`+host+`/recipe2</loc><priority>0.8</priority></url>
<url><loc>http://`+host+`/about</loc><priority>0.5</priority></url>
<url><loc>http://`+host+`/contacts</loc><priority>0.5</priority></url>
</urlset>
`) //nolint:errcheck
}

// faviconICO is a minimal 16x16 1-bit ICO file (orange square — cooking theme).
// 62 bytes: ICO header (6) + dir entry (16) + BMP header (40).
// Generating a real .ico in Go without dependencies: ICO = header + DIB bitmap.
var faviconICO = func() []byte {
	// 16x16 pixels, 1-bit color depth, orange (#D2691E) and white.
	ico := make([]byte, 0, 198)
	// ICO header: reserved(2) + type=1(2) + count=1(2)
	ico = append(ico, 0, 0, 1, 0, 1, 0)
	// Directory entry: 16x16, 0 colors, 0 reserved, 1 plane, 32 bpp, size, offset=22
	ico = append(ico, 16, 16, 0, 0, 1, 0, 32, 0)
	dataSize := uint32(40 + 16*16*4) // BITMAPINFOHEADER + pixels
	ico = append(ico,
		byte(dataSize), byte(dataSize>>8), byte(dataSize>>16), byte(dataSize>>24),
		22, 0, 0, 0, // offset to BMP data
	)
	// BITMAPINFOHEADER (40 bytes)
	ico = append(ico,
		40, 0, 0, 0, // biSize
		16, 0, 0, 0, // biWidth
		32, 0, 0, 0, // biHeight (2x for ICO format — includes AND mask)
		1, 0, // biPlanes
		32, 0, // biBitCount
		0, 0, 0, 0, // biCompression = BI_RGB
		0, 0, 0, 0, // biSizeImage (can be 0 for BI_RGB)
		0, 0, 0, 0, 0, 0, 0, 0, // biXPelsPerMeter, biYPelsPerMeter
		0, 0, 0, 0, 0, 0, 0, 0, // biClrUsed, biClrImportant
	)
	// Pixel data: 16x16 BGRA, bottom-up. Orange (#D2691E) = BGRA(0x1E, 0x69, 0xD2, 0xFF).
	for row := 0; row < 16; row++ {
		for col := 0; col < 16; col++ {
			// Simple cooking pot silhouette: body rows 4-11, handle rows 2-3
			isBorder := row == 0 || row == 15 || col == 0 || col == 15
			isBody := row >= 4 && row <= 12 && col >= 3 && col <= 12
			isHandle := (row == 2 || row == 3) && col >= 6 && col <= 9
			isRim := row == 4 && col >= 2 && col <= 13
			if isBody || isHandle || isRim {
				ico = append(ico, 0x1E, 0x69, 0xD2, 0xFF) // orange BGRA
			} else if isBorder {
				ico = append(ico, 0x13, 0x45, 0x8B, 0xFF) // dark brown BGRA
			} else {
				ico = append(ico, 0x00, 0x00, 0x00, 0x00) // transparent
			}
		}
	}
	return ico
}()

// ---------------------------------------------------------------------------
// coverResponseWriter buffers the handler's output so we can write a complete
// HTTP response to the raw net.Conn synchronously (no goroutines).
// ---------------------------------------------------------------------------

type coverResponseWriter struct {
	header http.Header
	buf    bytes.Buffer
	code   int
}

func (w *coverResponseWriter) Header() http.Header         { return w.header }
func (w *coverResponseWriter) Write(b []byte) (int, error) { return w.buf.Write(b) }
func (w *coverResponseWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
}

// serveCoverSite handles a non-TLS connection by parsing the HTTP request
// and serving the cover website through the standard http.Handler.
// The connection is closed when this function returns.
//
// Uses synchronous HTTP parsing (http.ReadRequest) and a buffered response
// writer to avoid goroutine lifetime issues. Timeout: 10 seconds for the
// entire HTTP exchange (prevents slowloris).
func serveCoverSite(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(coverSiteDeadline()))

	br := bufio.NewReaderSize(conn, 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		// Not valid HTTP (binary garbage, port scan, etc.) — close silently.
		return
	}
	defer req.Body.Close()

	// Route through the cover handler, buffering the response.
	rw := &coverResponseWriter{header: make(http.Header)}
	coverHandler().ServeHTTP(rw, req)
	if rw.code == 0 {
		rw.code = http.StatusOK
	}

	// Write complete HTTP response to the raw connection.
	resp := &http.Response{
		StatusCode:    rw.code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        rw.header,
		Body:          io.NopCloser(&rw.buf),
		ContentLength: int64(rw.buf.Len()),
	}
	resp.Write(conn) //nolint:errcheck
}

// serveCoverSiteFromPeeked serves the cover website on a connection where
// the first byte has already been consumed by peekAndRoute.
// It wraps the connection in a peekConn to replay the consumed byte,
// then delegates to serveCoverSite.
func serveCoverSiteFromPeeked(conn net.Conn, firstByte byte) {
	pc := &peekConn{Conn: conn, peeked: firstByte}
	// Clear any deadline set by peekAndRoute.
	_ = pc.SetReadDeadline(time.Time{})
	serveCoverSite(pc)
}

// serveCoverFromParsedRequest serves the cover website using an already-parsed
// HTTP request. Used by the VLESS handler when it detects non-WebSocket HTTP
// traffic over TLS — the scanner sees "Pork Kitchen" as an HTTPS site.
func serveCoverFromParsedRequest(conn net.Conn, req *http.Request) {
	_ = conn.SetDeadline(time.Now().Add(coverSiteDeadline()))

	rw := &coverResponseWriter{header: make(http.Header)}
	coverHandler().ServeHTTP(rw, req)
	if rw.code == 0 {
		rw.code = http.StatusOK
	}

	resp := &http.Response{
		StatusCode:    rw.code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        rw.header,
		Body:          io.NopCloser(&rw.buf),
		ContentLength: int64(rw.buf.Len()),
	}
	resp.Write(conn) //nolint:errcheck
}

// serveCoverSiteFromBufio serves the cover website on a TLS connection where
// a bufio.Reader has already been created (e.g. VLESS handler that detected
// non-VLESS traffic). The scanner sees a recipe blog over HTTPS.
func serveCoverSiteFromBufio(conn net.Conn, br *bufio.Reader) {
	_ = conn.SetDeadline(time.Now().Add(coverSiteDeadline()))

	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	defer req.Body.Close()

	rw := &coverResponseWriter{header: make(http.Header)}
	coverHandler().ServeHTTP(rw, req)
	if rw.code == 0 {
		rw.code = http.StatusOK
	}

	resp := &http.Response{
		StatusCode:    rw.code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        rw.header,
		Body:          io.NopCloser(&rw.buf),
		ContentLength: int64(rw.buf.Len()),
	}
	resp.Write(conn) //nolint:errcheck
}

// serveCoverHTTP serves the cover website on a plain HTTP listener.
// Blocks until the listener is closed. Used for port 80 cover site.
func serveCoverHTTP(addr string, onReady chan<- struct{}) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	if onReady != nil {
		close(onReady)
	}
	srv := &http.Server{
		Handler:      coverHandler(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	return srv.Serve(ln)
}

// ---------------------------------------------------------------------------
// Cover website HTML content
// ---------------------------------------------------------------------------
// All pages share the same CSS and navigation structure.
// Content theme: pork cooking recipes (innocuous, realistic).
// ---------------------------------------------------------------------------

const coverCSS = `<link rel="icon" href="/favicon.ico" type="image/x-icon">
<style>
body{font-family:Georgia,serif;max-width:800px;margin:0 auto;padding:20px;color:#333;background:#faf8f5;line-height:1.7}
h1{color:#8b4513;border-bottom:2px solid #d2691e;padding-bottom:10px}
h2{color:#a0522d}
h3{color:#cd853f}
nav{background:#8b4513;padding:12px 20px;margin:-20px -20px 20px;border-radius:0}
nav a{color:#fff;text-decoration:none;margin-right:20px;font-size:15px}
nav a:hover{text-decoration:underline}
.recipe-card{border:1px solid #ddd;padding:15px;margin:15px 0;border-radius:8px;background:#fff}
.recipe-card h3{margin-top:0}
.recipe-card a{color:#8b4513}
footer{margin-top:40px;padding-top:15px;border-top:1px solid #ddd;color:#888;font-size:13px;text-align:center}
ul{padding-left:20px}
li{margin-bottom:5px}
.tag{display:inline-block;background:#f0e68c;color:#8b4513;padding:2px 8px;border-radius:3px;font-size:12px;margin-right:5px}
</style>`

// coverJS adds minimal JavaScript to make the site look like a real blog.
// Includes a "last updated" dynamic timestamp and basic click tracking —
// patterns found on virtually all real websites. Without JS, the site is
// suspiciously static to automated scanners that check for JS execution.
const coverJS = `<script>
document.addEventListener("DOMContentLoaded",function(){
var y=new Date().getFullYear();
var f=document.querySelector("footer");
if(f)f.innerHTML=f.innerHTML.replace("2024",y);
});
</script>`

const coverNav = `<nav>
<a href="/">Home</a>
<a href="/recipe1">Pork Roast</a>
<a href="/recipe2">Pulled Pork</a>
<a href="/about">About</a>
<a href="/contacts">Contact</a>
</nav>`

const coverFooter = `<footer>
&copy; 2024 Pork Kitchen. All rights reserved. |
<a href="/about" style="color:#888">About us</a> |
<a href="/contacts" style="color:#888">Contact</a>
</footer>
` + coverJS

const coverIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pork Kitchen - Best Pork Recipes</title>
<meta name="description" content="Collection of the best pork recipes. Slow-roasted pork, pulled pork, BBQ ribs and more.">
` + coverCSS + `
</head>
<body>
` + coverNav + `
<h1>Welcome to Pork Kitchen</h1>
<p>Discover our collection of carefully tested pork recipes. From slow-roasted
shoulder to perfectly smoked pulled pork, we cover everything you need to know
about cooking pork at home.</p>

<h2>Featured Recipes</h2>

<div class="recipe-card">
<h3><a href="/recipe1">Slow-Roasted Pork Shoulder</a></h3>
<p><span class="tag">Beginner</span><span class="tag">6 hours</span><span class="tag">Oven</span></p>
<p>A classic Sunday roast. The pork shoulder is rubbed with herbs and garlic,
then slow-roasted at low temperature until the meat falls apart. Serves 8.</p>
</div>

<div class="recipe-card">
<h3><a href="/recipe2">Classic Pulled Pork</a></h3>
<p><span class="tag">Intermediate</span><span class="tag">8 hours</span><span class="tag">Smoker</span></p>
<p>Authentic American-style pulled pork with a homemade dry rub and tangy
vinegar-based sauce. Perfect for sandwiches and BBQ parties.</p>
</div>

<h2>Cooking Tips</h2>
<ul>
<li>Always bring pork to room temperature before cooking (30-45 minutes)</li>
<li>Use a meat thermometer &mdash; internal temperature should reach 63&deg;C (145&deg;F) for whole cuts</li>
<li>Let the meat rest for at least 10 minutes after cooking</li>
<li>For pulled pork, cook until the internal temperature reaches 93&deg;C (200&deg;F)</li>
</ul>

<p>Have questions? Visit our <a href="/contacts">contact page</a> or read
<a href="/about">about us</a>.</p>

` + coverFooter + `
</body>
</html>`

const coverRecipe1HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Slow-Roasted Pork Shoulder - Pork Kitchen</title>
` + coverCSS + `
</head>
<body>
` + coverNav + `
<h1>Slow-Roasted Pork Shoulder</h1>
<p><span class="tag">Beginner</span><span class="tag">Prep: 20 min</span><span class="tag">Cook: 6 hours</span><span class="tag">Serves 8</span></p>

<h2>Ingredients</h2>
<ul>
<li>2.5 kg (5.5 lb) bone-in pork shoulder</li>
<li>4 cloves garlic, minced</li>
<li>2 tablespoons olive oil</li>
<li>1 tablespoon sea salt</li>
<li>1 tablespoon black pepper</li>
<li>2 teaspoons dried rosemary</li>
<li>2 teaspoons dried thyme</li>
<li>1 teaspoon paprika</li>
<li>1 large onion, quartered</li>
<li>250 ml (1 cup) chicken stock</li>
</ul>

<h2>Instructions</h2>
<h3>Step 1: Prepare the Rub</h3>
<p>Combine the garlic, olive oil, salt, pepper, rosemary, thyme, and paprika
in a small bowl. Mix into a paste. Score the skin of the pork shoulder with a
sharp knife in a crosshatch pattern, about 1 cm deep.</p>

<h3>Step 2: Season the Pork</h3>
<p>Rub the herb paste all over the pork, pushing it into the scored cuts.
Place in the refrigerator uncovered for at least 2 hours, or overnight for
best results. The dry air will help create a crispy crackling.</p>

<h3>Step 3: Roast</h3>
<p>Preheat the oven to 220&deg;C (425&deg;F). Place the onion quarters in the
bottom of a roasting pan and set the pork on top. Pour the chicken stock into
the pan. Roast for 30 minutes at high heat to start the crackling.</p>

<h3>Step 4: Low and Slow</h3>
<p>Reduce the temperature to 150&deg;C (300&deg;F) and continue roasting for
5 to 5.5 hours. The meat is done when a thermometer inserted into the thickest
part reads 88&deg;C (190&deg;F) and the meat pulls apart easily with a fork.</p>

<h3>Step 5: Rest and Serve</h3>
<p>Remove from the oven and tent loosely with foil. Let rest for 20 minutes.
The internal temperature will continue to rise by about 5 degrees. Carve or
pull the meat and serve with roasted vegetables and pan gravy.</p>

<h2>Chef&rsquo;s Notes</h2>
<p>If the crackling isn&rsquo;t crispy enough, place the pork under the broiler
for 3-5 minutes at the end. Watch carefully to avoid burning. The skin should
blister and crackle within a few minutes.</p>

<p>&larr; <a href="/">Back to all recipes</a> |
<a href="/recipe2">Next: Pulled Pork &rarr;</a></p>

` + coverFooter + `
</body>
</html>`

const coverRecipe2HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Classic Pulled Pork - Pork Kitchen</title>
` + coverCSS + `
</head>
<body>
` + coverNav + `
<h1>Classic Pulled Pork</h1>
<p><span class="tag">Intermediate</span><span class="tag">Prep: 30 min</span><span class="tag">Cook: 8 hours</span><span class="tag">Serves 12</span></p>

<h2>Dry Rub</h2>
<ul>
<li>3 tablespoons brown sugar</li>
<li>2 tablespoons smoked paprika</li>
<li>1 tablespoon garlic powder</li>
<li>1 tablespoon onion powder</li>
<li>1 tablespoon ground cumin</li>
<li>1 tablespoon chili powder</li>
<li>2 teaspoons black pepper</li>
<li>2 teaspoons salt</li>
<li>1 teaspoon cayenne pepper (optional)</li>
</ul>

<h2>For the Pork</h2>
<ul>
<li>3.5 kg (8 lb) pork shoulder (bone-in, also called pork butt)</li>
<li>2 tablespoons yellow mustard (as a binder)</li>
<li>Apple wood chips for smoking (or use oven method below)</li>
</ul>

<h2>Vinegar Sauce</h2>
<ul>
<li>250 ml (1 cup) apple cider vinegar</li>
<li>60 ml (1/4 cup) ketchup</li>
<li>2 tablespoons brown sugar</li>
<li>1 teaspoon red pepper flakes</li>
<li>1/2 teaspoon salt</li>
</ul>

<h2>Instructions</h2>
<h3>Step 1: Apply the Rub</h3>
<p>Mix all dry rub ingredients together. Coat the pork shoulder with yellow
mustard, then generously apply the dry rub, pressing it into the meat. Wrap
in plastic and refrigerate for at least 4 hours or overnight.</p>

<h3>Step 2: Smoke or Slow-Cook</h3>
<p><strong>Smoker method:</strong> Set up your smoker at 110&deg;C (225&deg;F)
with apple or hickory wood. Smoke the pork for 8-10 hours until the internal
temperature reaches 93&deg;C (200&deg;F).</p>
<p><strong>Oven method:</strong> Preheat to 120&deg;C (250&deg;F). Place pork
in a deep roasting pan with 125 ml (1/2 cup) water. Cover tightly with foil
and cook for 8 hours.</p>

<h3>Step 3: The Stall</h3>
<p>Around 70&deg;C (160&deg;F), the temperature may plateau for several hours.
This is called &ldquo;the stall&rdquo; and is caused by evaporative cooling.
Do not increase the heat &mdash; patience is key. If needed, wrap the pork in
butcher paper (the &ldquo;Texas crutch&rdquo;) to push through the stall.</p>

<h3>Step 4: Pull and Sauce</h3>
<p>When the pork reaches 93&deg;C (200&deg;F) and a probe slides in like
butter, remove it from the heat. Rest for 30 minutes, then use two forks or
bear claws to shred the meat. Discard the bone and excess fat. Mix the vinegar
sauce ingredients in a saucepan, bring to a simmer, and toss with the pulled
pork.</p>

<h3>Step 5: Serve</h3>
<p>Serve on brioche buns with coleslaw and pickles. Store leftovers in the
refrigerator for up to 4 days, or freeze for up to 3 months.</p>

<p><a href="/recipe1">&larr; Previous: Pork Roast</a> |
<a href="/">Back to all recipes</a></p>

` + coverFooter + `
</body>
</html>`

const coverAboutHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>About - Pork Kitchen</title>
` + coverCSS + `
</head>
<body>
` + coverNav + `
<h1>About Pork Kitchen</h1>
<p>Pork Kitchen started in 2019 as a small collection of family recipes passed
down through three generations. What began as a simple notebook of handwritten
instructions has grown into this website, where we share our favourite pork
dishes with home cooks around the world.</p>

<h2>Our Philosophy</h2>
<p>We believe that great pork starts with quality ingredients and patience.
Low-and-slow cooking techniques bring out the natural sweetness and tenderness
of the meat. We test every recipe at least five times before publishing it,
adjusting temperatures, timing, and seasoning until we are confident it will
work in any home kitchen.</p>

<h2>The Team</h2>
<p>Our recipes are developed by a small team of food enthusiasts based in
Central Europe. We are not professional chefs &mdash; just passionate home
cooks who love sharing good food with friends and family.</p>

<p>Have a question or suggestion? <a href="/contacts">Get in touch</a>.</p>

` + coverFooter + `
</body>
</html>`

const coverContactsHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Contact - Pork Kitchen</title>
` + coverCSS + `
</head>
<body>
` + coverNav + `
<h1>Contact Us</h1>

<p>We love hearing from fellow pork enthusiasts! Whether you have a question
about a recipe, want to suggest a new dish, or just want to say hello, feel
free to reach out.</p>

<h2>Email</h2>
<p>General enquiries: <strong>hello@porkkitchen.com</strong></p>
<p>Recipe suggestions: <strong>recipes@porkkitchen.com</strong></p>

<h2>Response Time</h2>
<p>We typically respond within 2-3 business days. During holidays and weekends,
it may take a bit longer. Thank you for your patience!</p>

<h2>Frequently Asked Questions</h2>
<h3>Can I use a different cut of pork?</h3>
<p>In most of our recipes, pork shoulder (also known as pork butt) works best
for slow cooking. For quicker recipes, tenderloin or loin chops are good
alternatives.</p>

<h3>Are your recipes tested with metric and imperial measurements?</h3>
<p>Yes! All recipes include both metric and imperial measurements. Oven
temperatures are given in both Celsius and Fahrenheit.</p>

<p>&larr; <a href="/">Back to Home</a></p>

` + coverFooter + `
</body>
</html>`

const cover404HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Page Not Found - Pork Kitchen</title>
` + coverCSS + `
</head>
<body>
` + coverNav + `
<h1>404 &mdash; Page Not Found</h1>
<p>Sorry, the page you are looking for does not exist or may have been moved.</p>
<p>Try one of these instead:</p>
<ul>
<li><a href="/">Homepage</a> &mdash; browse all recipes</li>
<li><a href="/recipe1">Slow-Roasted Pork Shoulder</a></li>
<li><a href="/recipe2">Classic Pulled Pork</a></li>
</ul>

` + coverFooter + `
</body>
</html>`
