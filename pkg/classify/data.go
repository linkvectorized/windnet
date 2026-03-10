package classify

// domainCompany maps root domains to company names
var domainCompany = map[string]string{
	// Apple
	"apple.com":            "Apple Inc",
	"icloud.com":           "Apple Inc",
	"mzstatic.com":         "Apple Inc",
	"apple-cloudkit.com":   "Apple Inc",
	"appattest.apple.com":  "Apple Inc",
	"cdn-apple.com":        "Apple Inc",
	"apple-mapkit.com":     "Apple Inc",
	"push.apple.com":       "Apple Inc",

	// Google
	"google.com":           "Google LLC",
	"googleapis.com":       "Google LLC",
	"googleusercontent.com":"Google LLC",
	"gstatic.com":          "Google LLC",
	"googlevideo.com":      "Google LLC",
	"ytimg.com":            "Google LLC",
	"youtube.com":          "Google LLC",
	"ggpht.com":            "Google LLC",
	"googleadservices.com": "Google LLC",
	"googlesyndication.com":"Google LLC",
	"doubleclick.net":      "Google LLC",
	"google-analytics.com": "Google LLC",
	"googletagmanager.com": "Google LLC",
	"googleoptimize.com":   "Google LLC",
	"recaptcha.net":        "Google LLC",
	"chromium.org":         "Google LLC",

	// Amazon / AWS
	"amazon.com":           "Amazon",
	"amazonaws.com":        "Amazon AWS",
	"cloudfront.net":       "Amazon AWS",
	"awsstatic.com":        "Amazon AWS",
	"amazonvideo.com":      "Amazon",
	"primevideo.com":       "Amazon",

	// Microsoft
	"microsoft.com":        "Microsoft",
	"windows.com":          "Microsoft",
	"live.com":             "Microsoft",
	"office.com":           "Microsoft",
	"office365.com":        "Microsoft",
	"microsoftonline.com":  "Microsoft",
	"azure.com":            "Microsoft Azure",
	"azureedge.net":        "Microsoft Azure",
	"msn.com":              "Microsoft",
	"bing.com":             "Microsoft",
	"outlook.com":          "Microsoft",
	"skype.com":            "Microsoft",
	"xbox.com":             "Microsoft",
	"visualstudio.com":     "Microsoft",
	"github.com":           "GitHub (Microsoft)",
	"githubusercontent.com":"GitHub (Microsoft)",
	"githubassets.com":     "GitHub (Microsoft)",

	// Meta
	"facebook.com":         "Meta",
	"instagram.com":        "Meta",
	"whatsapp.com":         "Meta",
	"fbcdn.net":            "Meta",
	"fbsbx.com":            "Meta",
	"cdninstagram.com":     "Meta",
	"oculus.com":           "Meta",

	// Cloudflare
	"cloudflare.com":       "Cloudflare",
	"cloudflare-dns.com":   "Cloudflare",
	"cloudflareinsights.com":"Cloudflare",
	"workers.dev":          "Cloudflare",
	"pages.dev":            "Cloudflare",

	// Akamai
	"akamai.net":           "Akamai",
	"akamaiedge.net":       "Akamai",
	"akamaihd.net":         "Akamai",
	"edgekey.net":          "Akamai",
	"edgesuite.net":        "Akamai",

	// Fastly
	"fastly.net":           "Fastly",
	"fastlylabs.com":       "Fastly",

	// Slack
	"slack.com":            "Slack",
	"slack-edge.com":       "Slack",
	"slack-msgs.com":       "Slack",
	"slack-redir.net":      "Slack",

	// Spotify
	"spotify.com":          "Spotify",
	"scdn.co":              "Spotify",
	"spotilocal.com":       "Spotify",

	// Zoom
	"zoom.us":              "Zoom",
	"zoomgov.com":          "Zoom",

	// Dropbox
	"dropbox.com":          "Dropbox",
	"dropboxstatic.com":    "Dropbox",

	// Twilio / SendGrid
	"twilio.com":           "Twilio",
	"sendgrid.net":         "Twilio SendGrid",

	// Stripe
	"stripe.com":           "Stripe",
	"stripecdn.com":        "Stripe",

	// Cloudflare R2 / misc CDN
	"r2.dev":               "Cloudflare",

	// Apple telemetry specifics (subdomains that are telemetry)
	"metrics.apple.com":    "Apple Inc",
	"xp.apple.com":         "Apple Inc",

	// Misc
	"digicert.com":         "DigiCert (CA)",
	"letsencrypt.org":      "Let's Encrypt (CA)",
	"ocsp.pki.goog":        "Google (CA)",
	"crl.pki.goog":         "Google (CA)",
}

// trackerDomains — ad tracking, analytics, fingerprinting
var trackerDomains = map[string]bool{
	"google-analytics.com":   true,
	"analytics.google.com":   true,
	"googletagmanager.com":   true,
	"googleadservices.com":   true,
	"googlesyndication.com":  true,
	"doubleclick.net":        true,
	"adservice.google.com":   true,
	"pagead2.googlesyndication.com": true,
	"facebook.com":           true,
	"connect.facebook.net":   true,
	"pixel.facebook.com":     true,
	"fbcdn.net":              true,
	"scorecardresearch.com":  true,
	"quantserve.com":         true,
	"mixpanel.com":           true,
	"segment.io":             true,
	"segment.com":            true,
	"amplitude.com":          true,
	"heap.io":                true,
	"hotjar.com":             true,
	"intercom.io":            true,
	"intercom.com":           true,
	"optimizely.com":         true,
	"mouseflow.com":          true,
	"fullstory.com":          true,
	"logrocket.com":          true,
	"datadog-rum.com":        true,
	"newrelic.com":           true,
	"nr-data.net":            true,
	"sentry.io":              true,
	"bugsnag.com":            true,
	"rollbar.com":            true,
	"statcounter.com":        true,
	"chartbeat.com":          true,
	"parsely.com":            true,
	"addthis.com":            true,
	"sharethis.com":          true,
	"outbrain.com":           true,
	"taboola.com":            true,
	"rubiconproject.com":     true,
	"pubmatic.com":           true,
	"openx.net":              true,
	"appnexus.com":           true,
	"criteo.com":             true,
	"criteo.net":             true,
	"moatads.com":            true,
	"adsrvr.org":             true,
	"advertising.com":        true,
	"adnxs.com":              true,
	"amazon-adsystem.com":    true,
	"cloudflareinsights.com": true,
}

// telemetryDomains — OS and app phone-home / diagnostics
var telemetryDomains = map[string]bool{
	// Apple
	"telemetry.apple.com":          true,
	"configuration.apple.com":      true,
	"gsa.apple.com":                true,
	"mesu.apple.com":               true,
	"captive.apple.com":            true,
	"ocsp.apple.com":               true,
	"crl.apple.com":                true,
	"xp.apple.com":                 true,
	"metrics.apple.com":            true,
	"bag.itunes.apple.com":         true,
	"init.itunes.apple.com":        true,
	"feedback.apple.com":           true,
	"api.apple-cloudkit.com":       true,

	// Microsoft
	"vortex.data.microsoft.com":    true,
	"settings-win.data.microsoft.com": true,
	"telemetry.microsoft.com":      true,
	"watson.microsoft.com":         true,
	"watson.telemetry.microsoft.com": true,
	"oca.microsoft.com":            true,
	"sqm.microsoft.com":            true,
	"update.microsoft.com":         true,

	// Google / Chrome
	"safebrowsing.googleapis.com":  true,
	"update.googleapis.com":        true,
	"clients1.google.com":          true,
	"clients2.google.com":          true,
	"clients4.google.com":          true,
	"chrome.google.com":            true,

	// Mozilla
	"telemetry.mozilla.org":        true,
	"incoming.telemetry.mozilla.org": true,
	"normandy.cdn.mozilla.net":     true,
	"firefox.settings.services.mozilla.com": true,

	// Adobe
	"cc-api-data.adobe.io":         true,
	"genuine.adobe.com":            true,
	"lcs-cops.adobe.io":            true,
}

// cloudProviders — legitimate cloud/CDN infrastructure
var cloudProviders = map[string]bool{
	"amazonaws.com":   true,
	"cloudfront.net":  true,
	"azure.com":       true,
	"azureedge.net":   true,
	"cloudflare.com":  true,
	"fastly.net":      true,
	"akamai.net":      true,
	"akamaiedge.net":  true,
	"edgekey.net":     true,
	"edgesuite.net":   true,
	"workers.dev":     true,
	"pages.dev":       true,
	"herokuapp.com":   true,
	"vercel.app":      true,
	"netlify.app":     true,
	"render.com":      true,
}
