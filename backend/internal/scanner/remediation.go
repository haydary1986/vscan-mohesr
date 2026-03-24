package scanner

// RemediationGuide provides step-by-step fix instructions for a specific security check.
type RemediationGuide struct {
	CheckName    string            `json:"check_name"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	Priority     string            `json:"priority"`      // critical, high, medium, low
	TimeEstimate string            `json:"time_estimate"` // "5 minutes", "30 minutes"
	Guides       map[string]string `json:"guides"`        // key: server type, value: markdown steps
}

// RemediationDB maps check names to their remediation guides.
var RemediationDB = map[string]RemediationGuide{}

func init() {
	populateRemediationDB()
}

func populateRemediationDB() {
	// -------------------------------------------------------------------------
	// 1. HSTS
	// -------------------------------------------------------------------------
	RemediationDB["HSTS"] = RemediationGuide{
		CheckName:    "HSTS",
		Title:        "Enable HTTP Strict Transport Security (HSTS)",
		Description:  "HSTS forces browsers to only connect via HTTPS, preventing downgrade attacks and cookie hijacking.",
		Priority:     "critical",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Enable HSTS

1. Log in to your **Cloudflare dashboard**
2. Select your domain
3. Go to **SSL/TLS** > **Edge Certificates**
4. Scroll to **HTTP Strict Transport Security (HSTS)**
5. Click **Enable HSTS**
6. Configure:
   - **Max-Age**: 12 months (recommended)
   - **Include subdomains**: Yes
   - **Preload**: Yes
   - **No-Sniff**: Yes
7. Click **Save**

> Cloudflare will add the header automatically to all responses.`,

			"apache": `## Apache - Enable HSTS

Add to your ` + "`" + `.htaccess` + "`" + ` or virtual host configuration:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
` + "```" + `

Make sure ` + "`" + `mod_headers` + "`" + ` is enabled:

` + "```bash" + `
sudo a2enmod headers
sudo systemctl restart apache2
` + "```",

			"nginx": `## Nginx - Enable HSTS

Add inside your ` + "`" + `server` + "`" + ` block (HTTPS only):

` + "```nginx" + `
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
` + "```" + `

Then reload:

` + "```bash" + `
sudo nginx -t && sudo systemctl reload nginx
` + "```" + `

> Only add this to HTTPS server blocks, not HTTP.`,

			"litespeed": `## LiteSpeed - Enable HSTS

**Option 1: Via .htaccess**

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
` + "```" + `

**Option 2: Via LiteSpeed Web Admin**

1. Go to **Configuration** > **Virtual Hosts** > your host > **Context**
2. Add a **Static Context** for ` + "`" + `/` + "`" + `
3. Under **Header Operations**, add:
   ` + "`" + `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` + "`" + `
4. Restart LiteSpeed`,

			"plesk": `## Plesk - Enable HSTS

1. Log in to **Plesk**
2. Go to **Domains** > select your domain
3. Click **Apache & nginx Settings**
4. In **Additional Apache directives**, add:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
` + "```" + `

5. Click **OK** / **Apply**`,

			"cpanel": `## cPanel - Enable HSTS

**Option 1: Via .htaccess**

1. Open **File Manager** in cPanel
2. Navigate to your document root
3. Edit ` + "`" + `.htaccess` + "`" + `
4. Add:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
` + "```" + `

**Option 2: Via cPanel UI (if available)**

1. Go to **Security** > **HTTP Strict Transport Security**
2. Enable for your domain with max-age 12 months`,

			"wordpress": `## WordPress - Enable HSTS

**Option 1: Plugin (Recommended)**

Install and activate **HTTP Headers** or **Really Simple SSL Pro** plugin:
1. Go to **Plugins** > **Add New**
2. Search for "HTTP Headers" or "Really Simple SSL"
3. Activate and configure HSTS settings

**Option 2: Via wp-config.php (advanced)**

Add to your theme's ` + "`" + `functions.php` + "`" + ` or a custom plugin:

` + "```php" + `
add_action('send_headers', function() {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
});
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 2. Content Security Policy
	// -------------------------------------------------------------------------
	RemediationDB["Content Security Policy"] = RemediationGuide{
		CheckName:    "Content Security Policy",
		Title:        "Configure Content Security Policy (CSP)",
		Description:  "CSP prevents XSS attacks by controlling which resources the browser is allowed to load.",
		Priority:     "high",
		TimeEstimate: "30 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Add CSP Header

**Option 1: Transform Rules**

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Click **Create rule**
3. Set:
   - **Header name**: ` + "`" + `Content-Security-Policy` + "`" + `
   - **Value**: ` + "`" + `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';` + "`" + `
4. Deploy

**Option 2: Cloudflare Workers**

Create a Worker that adds the CSP header to responses.`,

			"apache": `## Apache - Add CSP Header

Add to ` + "`" + `.htaccess` + "`" + ` or virtual host:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
</IfModule>
` + "```" + `

> **Tip**: Start with ` + "`" + `Content-Security-Policy-Report-Only` + "`" + ` to test without breaking anything.`,

			"nginx": `## Nginx - Add CSP Header

Add inside your ` + "`" + `server` + "`" + ` block:

` + "```nginx" + `
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';" always;
` + "```" + `

Then reload:

` + "```bash" + `
sudo nginx -t && sudo systemctl reload nginx
` + "```",

			"litespeed": `## LiteSpeed - Add CSP Header

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
</IfModule>
` + "```",

			"plesk": `## Plesk - Add CSP Header

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. In **Additional Apache directives**:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
</IfModule>
` + "```",

			"cpanel": `## cPanel - Add CSP Header

Edit ` + "`" + `.htaccess` + "`" + ` in your document root:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
</IfModule>
` + "```",

			"wordpress": `## WordPress - Add CSP Header

**Option 1: Plugin**

Install **HTTP Headers** or **WP Content Security Policy** plugin.

**Option 2: functions.php**

` + "```php" + `
add_action('send_headers', function() {
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';");
});
` + "```" + `

> WordPress often requires ` + "`" + `'unsafe-inline'` + "`" + ` for scripts/styles due to inline code in themes and plugins.`,
		},
	}

	// -------------------------------------------------------------------------
	// 3. X-Frame-Options
	// -------------------------------------------------------------------------
	RemediationDB["X-Frame-Options"] = RemediationGuide{
		CheckName:    "X-Frame-Options",
		Title:        "Set X-Frame-Options Header",
		Description:  "Prevents your site from being embedded in iframes, protecting against clickjacking attacks.",
		Priority:     "high",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - X-Frame-Options

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Add header:
   - **Name**: ` + "`" + `X-Frame-Options` + "`" + `
   - **Value**: ` + "`" + `DENY` + "`" + ` (or ` + "`" + `SAMEORIGIN` + "`" + ` if you embed your own pages)`,

			"apache": `## Apache - X-Frame-Options

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
</IfModule>
` + "```",

			"nginx": `## Nginx - X-Frame-Options

` + "```nginx" + `
add_header X-Frame-Options "DENY" always;
` + "```",

			"litespeed": `## LiteSpeed - X-Frame-Options

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
</IfModule>
` + "```",

			"plesk": `## Plesk - X-Frame-Options

In **Apache & nginx Settings** > **Additional Apache directives**:

` + "```apache" + `
Header always set X-Frame-Options "DENY"
` + "```",

			"cpanel": `## cPanel - X-Frame-Options

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
</IfModule>
` + "```",

			"wordpress": `## WordPress - X-Frame-Options

WordPress sends ` + "`" + `X-Frame-Options: SAMEORIGIN` + "`" + ` by default for admin pages. To set it site-wide:

` + "```php" + `
add_action('send_headers', function() {
    header('X-Frame-Options: DENY');
});
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 4. Permissions-Policy
	// -------------------------------------------------------------------------
	RemediationDB["Permissions-Policy"] = RemediationGuide{
		CheckName:    "Permissions-Policy",
		Title:        "Configure Permissions-Policy Header",
		Description:  "Controls which browser features (camera, microphone, geolocation, etc.) your site can use.",
		Priority:     "medium",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Permissions-Policy

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Add:
   - **Name**: ` + "`" + `Permissions-Policy` + "`" + `
   - **Value**: ` + "`" + `camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()` + "`",

			"apache": `## Apache - Permissions-Policy

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
</IfModule>
` + "```",

			"nginx": `## Nginx - Permissions-Policy

` + "```nginx" + `
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()" always;
` + "```",

			"litespeed": `## LiteSpeed - Permissions-Policy

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
</IfModule>
` + "```",

			"plesk": `## Plesk - Permissions-Policy

In **Apache & nginx Settings**:

` + "```apache" + `
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
` + "```",

			"cpanel": `## cPanel - Permissions-Policy

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
</IfModule>
` + "```",

			"wordpress": `## WordPress - Permissions-Policy

` + "```php" + `
add_action('send_headers', function() {
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()');
});
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 5. HTTPS Redirect
	// -------------------------------------------------------------------------
	RemediationDB["HTTP to HTTPS Redirect"] = RemediationGuide{
		CheckName:    "HTTP to HTTPS Redirect",
		Title:        "Force HTTPS Redirect",
		Description:  "Ensures all HTTP traffic is automatically redirected to HTTPS for encrypted connections.",
		Priority:     "critical",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Force HTTPS

1. Go to **SSL/TLS** > **Edge Certificates**
2. Enable **Always Use HTTPS**
3. Optionally enable **Automatic HTTPS Rewrites** under SSL/TLS settings`,

			"apache": `## Apache - Force HTTPS

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
` + "```" + `

Or in the virtual host:

` + "```apache" + `
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>
` + "```",

			"nginx": `## Nginx - Force HTTPS

` + "```nginx" + `
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}
` + "```",

			"litespeed": `## LiteSpeed - Force HTTPS

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
` + "```",

			"plesk": `## Plesk - Force HTTPS

1. Go to **Domains** > your domain > **Hosting Settings**
2. Check **Permanent SEO-safe 301 redirect from HTTP to HTTPS**
3. Click **OK**`,

			"cpanel": `## cPanel - Force HTTPS

1. Go to **Domains** > **Redirects**
2. Or edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
` + "```",

			"wordpress": `## WordPress - Force HTTPS

1. Go to **Settings** > **General**
2. Change both URLs to ` + "`" + `https://` + "`" + `
3. Install **Really Simple SSL** plugin for automatic fixing
4. Add to ` + "`" + `wp-config.php` + "`" + `:

` + "```php" + `
define('FORCE_SSL_ADMIN', true);
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 6. TLS Version
	// -------------------------------------------------------------------------
	RemediationDB["TLS Version"] = RemediationGuide{
		CheckName:    "TLS Version",
		Title:        "Set Minimum TLS 1.2",
		Description:  "Disable old TLS versions (1.0, 1.1) that have known vulnerabilities.",
		Priority:     "high",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Minimum TLS Version

1. Go to **SSL/TLS** > **Edge Certificates**
2. Find **Minimum TLS Version**
3. Set to **TLS 1.2** (recommended)`,

			"apache": `## Apache - Minimum TLS 1.2

` + "```apache" + `
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite HIGH:!aNULL:!MD5:!3DES
SSLHonorCipherOrder on
` + "```" + `

Restart Apache after changes.`,

			"nginx": `## Nginx - Minimum TLS 1.2

` + "```nginx" + `
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5:!3DES;
ssl_prefer_server_ciphers on;
` + "```" + `

` + "```bash" + `
sudo nginx -t && sudo systemctl reload nginx
` + "```",

			"litespeed": `## LiteSpeed - Minimum TLS 1.2

1. In **LiteSpeed Web Admin** > **Listeners** > your listener
2. Set **SSL Protocol Version**: TLSv1.2 TLSv1.3
3. Restart LiteSpeed`,

			"plesk": `## Plesk - Minimum TLS 1.2

1. Go to **Tools & Settings** > **SSL/TLS Certificates**
2. Under **Apache SSL settings**, disable TLS 1.0 and 1.1
3. Or edit Apache/Nginx configuration directly`,

			"cpanel": `## cPanel - Minimum TLS 1.2

1. Log in to **WHM** (root access required)
2. Go to **Service Configuration** > **Apache Configuration** > **Global Configuration**
3. Set **SSL/TLS Protocols**: TLSv1.2 TLSv1.3
4. Rebuild Apache configuration`,
		},
	}

	// -------------------------------------------------------------------------
	// 7. HTTP Methods
	// -------------------------------------------------------------------------
	RemediationDB["Dangerous Methods"] = RemediationGuide{
		CheckName:    "Dangerous Methods",
		Title:        "Block Dangerous HTTP Methods",
		Description:  "Disable TRACE, DELETE, PUT, and other dangerous HTTP methods that could be exploited.",
		Priority:     "medium",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block HTTP Methods

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`" + `(http.request.method in {"TRACE" "DELETE" "PUT" "PATCH" "OPTIONS"})` + "`" + `
   - **Action**: Block`,

			"apache": `## Apache - Block Dangerous Methods

` + "```apache" + `
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
` + "```" + `

To specifically disable TRACE:

` + "```apache" + `
TraceEnable Off
` + "```",

			"nginx": `## Nginx - Block Dangerous Methods

` + "```nginx" + `
if ($request_method !~ ^(GET|HEAD|POST)$ ) {
    return 405;
}
` + "```",

			"litespeed": `## LiteSpeed - Block Dangerous Methods

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(TRACE|DELETE|TRACK|PUT) [NC]
RewriteRule .* - [F]
` + "```",

			"plesk": `## Plesk - Block Dangerous Methods

In **Apache & nginx Settings** > **Additional Apache directives**:

` + "```apache" + `
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
TraceEnable Off
` + "```",

			"cpanel": `## cPanel - Block Dangerous Methods

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(TRACE|DELETE|TRACK|PUT) [NC]
RewriteRule .* - [F]
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 8. DMARC
	// -------------------------------------------------------------------------
	RemediationDB["DMARC Record"] = RemediationGuide{
		CheckName:    "DMARC Record",
		Title:        "Configure DMARC DNS Record",
		Description:  "DMARC prevents email spoofing by telling receivers how to handle unauthenticated emails from your domain.",
		Priority:     "high",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Add DMARC Record

1. Go to **DNS** > **Records**
2. Click **Add record**
3. Set:
   - **Type**: TXT
   - **Name**: ` + "`" + `_dmarc` + "`" + `
   - **Content**: ` + "`" + `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc@yourdomain.com; fo=1; adkim=s; aspf=s` + "`" + `

**Progressive rollout recommended:**
- Start with ` + "`" + `p=none` + "`" + ` (monitor only)
- Move to ` + "`" + `p=quarantine` + "`" + ` after reviewing reports
- Finally set ` + "`" + `p=reject` + "`" + ` for full protection`,

			"apache": `## DNS Provider - Add DMARC Record

DMARC is a **DNS record**, not a server configuration. Add this TXT record at your DNS provider:

- **Host**: ` + "`" + `_dmarc` + "`" + `
- **Type**: TXT
- **Value**: ` + "`" + `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc@yourdomain.com; fo=1` + "`",

			"nginx": `## DNS Provider - Add DMARC Record

DMARC is a **DNS record**. Add this TXT record:

- **Host**: ` + "`" + `_dmarc` + "`" + `
- **Type**: TXT
- **Value**: ` + "`" + `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; fo=1` + "`",

			"litespeed": `## DNS Provider - Add DMARC Record

Add a TXT record at your DNS provider:

- **Host**: ` + "`" + `_dmarc` + "`" + `
- **Value**: ` + "`" + `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; fo=1` + "`",

			"plesk": `## Plesk - Add DMARC Record

1. Go to **Domains** > your domain > **DNS Settings**
2. Add a TXT record:
   - **Host**: ` + "`" + `_dmarc` + "`" + `
   - **Value**: ` + "`" + `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; fo=1` + "`",

			"cpanel": `## cPanel - Add DMARC Record

1. Go to **Zone Editor** or **Advanced DNS Zone Editor**
2. Add a TXT record:
   - **Name**: ` + "`" + `_dmarc.yourdomain.com` + "`" + `
   - **Type**: TXT
   - **Record**: ` + "`" + `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; fo=1` + "`",
		},
	}

	// -------------------------------------------------------------------------
	// 9. SPF
	// -------------------------------------------------------------------------
	RemediationDB["SPF Record"] = RemediationGuide{
		CheckName:    "SPF Record",
		Title:        "Configure SPF DNS Record",
		Description:  "SPF specifies which mail servers are authorized to send email on behalf of your domain.",
		Priority:     "high",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Add SPF Record

1. Go to **DNS** > **Records**
2. Add a TXT record:
   - **Name**: ` + "`" + `@` + "`" + `
   - **Content**: ` + "`" + `v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all` + "`" + `

Adjust ` + "`" + `include:` + "`" + ` entries based on your email provider:
- **Google Workspace**: ` + "`" + `include:_spf.google.com` + "`" + `
- **Microsoft 365**: ` + "`" + `include:spf.protection.outlook.com` + "`" + `
- **No email**: ` + "`" + `v=spf1 -all` + "`" + ``,

			"apache": `## DNS Provider - Add SPF Record

Add a TXT record at your DNS provider:

- **Host**: ` + "`" + `@` + "`" + ` (root domain)
- **Type**: TXT
- **Value**: ` + "`" + `v=spf1 include:_spf.google.com -all` + "`" + `

Adjust based on your mail provider.`,

			"nginx": `## DNS Provider - Add SPF Record

SPF is a DNS record. Add at your DNS provider:

- **Type**: TXT
- **Host**: ` + "`" + `@` + "`" + `
- **Value**: ` + "`" + `v=spf1 include:_spf.google.com -all` + "`",

			"litespeed": `## DNS Provider - Add SPF Record

Add at your DNS provider:

- **Type**: TXT
- **Host**: ` + "`" + `@` + "`" + `
- **Value**: ` + "`" + `v=spf1 include:_spf.google.com -all` + "`",

			"plesk": `## Plesk - Add SPF Record

1. Go to **Domains** > your domain > **DNS Settings**
2. Add a TXT record:
   - **Host**: (leave blank for root)
   - **Value**: ` + "`" + `v=spf1 include:_spf.google.com -all` + "`",

			"cpanel": `## cPanel - Add SPF Record

1. Go to **Email** > **Email Deliverability**
2. Or manually via **Zone Editor**:
   - **Name**: ` + "`" + `yourdomain.com` + "`" + `
   - **Type**: TXT
   - **Record**: ` + "`" + `v=spf1 include:_spf.google.com -all` + "`",
		},
	}

	// -------------------------------------------------------------------------
	// 10. Mixed Content
	// -------------------------------------------------------------------------
	RemediationDB["Mixed Content Check"] = RemediationGuide{
		CheckName:    "Mixed Content Check",
		Title:        "Fix Mixed Content Issues",
		Description:  "Mixed content occurs when HTTPS pages load resources over HTTP, weakening security.",
		Priority:     "high",
		TimeEstimate: "30 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Fix Mixed Content

1. Go to **SSL/TLS** > **Edge Certificates**
2. Enable **Automatic HTTPS Rewrites**
   - This automatically fixes mixed content by rewriting HTTP URLs to HTTPS

> This is the easiest fix and works for most cases.`,

			"apache": `## Apache - Fix Mixed Content

1. **Add CSP upgrade directive** to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "upgrade-insecure-requests"
</IfModule>
` + "```" + `

2. **Search and replace** HTTP URLs in your database/content with HTTPS equivalents.`,

			"nginx": `## Nginx - Fix Mixed Content

Add to your server block:

` + "```nginx" + `
add_header Content-Security-Policy "upgrade-insecure-requests" always;
` + "```" + `

Also update hardcoded HTTP URLs in your application.`,

			"litespeed": `## LiteSpeed - Fix Mixed Content

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "upgrade-insecure-requests"
</IfModule>
` + "```",

			"plesk": `## Plesk - Fix Mixed Content

In **Apache & nginx Settings**:

` + "```apache" + `
Header always set Content-Security-Policy "upgrade-insecure-requests"
` + "```",

			"cpanel": `## cPanel - Fix Mixed Content

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "upgrade-insecure-requests"
</IfModule>
` + "```",

			"wordpress": `## WordPress - Fix Mixed Content

1. Install **Really Simple SSL** plugin (auto-fixes most mixed content)
2. Or install **Better Search Replace** plugin:
   - Search: ` + "`" + `http://yourdomain.com` + "`" + `
   - Replace: ` + "`" + `https://yourdomain.com` + "`" + `
   - Run on all tables
3. Update ` + "`" + `wp-config.php` + "`" + `:

` + "```php" + `
define('FORCE_SSL_ADMIN', true);
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 11. Server Header
	// -------------------------------------------------------------------------
	RemediationDB["Server Header Exposure"] = RemediationGuide{
		CheckName:    "Server Header Exposure",
		Title:        "Hide Server Header",
		Description:  "The Server header reveals your web server software and version, helping attackers target known vulnerabilities.",
		Priority:     "medium",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Hide Server Header

Cloudflare automatically replaces the origin server header with ` + "`" + `server: cloudflare` + "`" + `.

To remove it entirely:
1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. **Remove** the ` + "`" + `Server` + "`" + ` header`,

			"apache": `## Apache - Hide Server Header

In ` + "`" + `httpd.conf` + "`" + ` or ` + "`" + `apache2.conf` + "`" + `:

` + "```apache" + `
ServerTokens Prod
ServerSignature Off
` + "```" + `

To fully remove, install ` + "`" + `mod_security` + "`" + `:

` + "```apache" + `
SecServerSignature " "
` + "```",

			"nginx": `## Nginx - Hide Server Header

In ` + "`" + `nginx.conf` + "`" + ` (http block):

` + "```nginx" + `
server_tokens off;
` + "```" + `

To fully remove the header, install ` + "`" + `headers-more-nginx-module` + "`" + `:

` + "```nginx" + `
more_clear_headers Server;
` + "```",

			"litespeed": `## LiteSpeed - Hide Server Header

1. In **LiteSpeed Web Admin** > **Configuration** > **Server** > **General**
2. Set **Server Signature**: No
3. Or add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
ServerSignature Off
` + "```",

			"plesk": `## Plesk - Hide Server Header

1. Edit Apache configuration via **Apache & nginx Settings**
2. Add:

` + "```apache" + `
ServerTokens Prod
ServerSignature Off
` + "```",

			"cpanel": `## cPanel - Hide Server Header

1. In WHM: **Service Configuration** > **Apache Configuration** > **Global Configuration**
2. Set **ServerTokens** to ` + "`" + `Prod` + "`" + `
3. Set **ServerSignature** to ` + "`" + `Off` + "`",
		},
	}

	// -------------------------------------------------------------------------
	// 12. X-Powered-By
	// -------------------------------------------------------------------------
	RemediationDB["X-Powered-By Exposure"] = RemediationGuide{
		CheckName:    "X-Powered-By Exposure",
		Title:        "Remove X-Powered-By Header",
		Description:  "The X-Powered-By header reveals your backend technology (PHP, ASP.NET, etc.), aiding attackers.",
		Priority:     "medium",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Remove X-Powered-By

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Add rule to **Remove** header: ` + "`" + `X-Powered-By` + "`",

			"apache": `## Apache - Remove X-Powered-By

For PHP, edit ` + "`" + `php.ini` + "`" + `:

` + "```ini" + `
expose_php = Off
` + "```" + `

Or via ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always unset X-Powered-By
</IfModule>
` + "```",

			"nginx": `## Nginx - Remove X-Powered-By

` + "```nginx" + `
proxy_hide_header X-Powered-By;
fastcgi_hide_header X-Powered-By;
` + "```" + `

Or with ` + "`" + `headers-more` + "`" + ` module:

` + "```nginx" + `
more_clear_headers X-Powered-By;
` + "```",

			"litespeed": `## LiteSpeed - Remove X-Powered-By

Edit ` + "`" + `php.ini` + "`" + `:

` + "```ini" + `
expose_php = Off
` + "```" + `

Or in ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
Header always unset X-Powered-By
` + "```",

			"plesk": `## Plesk - Remove X-Powered-By

1. Go to **Domains** > your domain > **PHP Settings**
2. Set ` + "`" + `expose_php` + "`" + ` to ` + "`" + `Off` + "`" + `
3. Or add to Apache directives:

` + "```apache" + `
Header always unset X-Powered-By
` + "```",

			"cpanel": `## cPanel - Remove X-Powered-By

1. Go to **MultiPHP INI Editor**
2. Set ` + "`" + `expose_php` + "`" + ` = ` + "`" + `Off` + "`" + `
3. Or edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_headers.c>
    Header always unset X-Powered-By
</IfModule>
` + "```",

			"wordpress": `## WordPress - Remove X-Powered-By

Add to ` + "`" + `functions.php` + "`" + `:

` + "```php" + `
header_remove('X-Powered-By');
` + "```" + `

And in ` + "`" + `php.ini` + "`" + `:

` + "```ini" + `
expose_php = Off
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 13. WordPress Version
	// -------------------------------------------------------------------------
	RemediationDB["WordPress Version"] = RemediationGuide{
		CheckName:    "WordPress Version",
		Title:        "Hide WordPress Version",
		Description:  "Exposing the WordPress version helps attackers find known vulnerabilities for that specific version.",
		Priority:     "medium",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Hide WP Version

Use a **Cloudflare Worker** to strip the generator meta tag, or handle it at the WordPress level (see WordPress guide).`,

			"apache": `## Apache - Hide WP Version

This is best handled at the WordPress application level. See the WordPress guide.

Alternatively, use ` + "`" + `mod_substitute` + "`" + ` to strip the meta tag (not recommended for performance).`,

			"nginx": `## Nginx - Hide WP Version

Use ` + "`" + `sub_filter` + "`" + ` to remove the generator tag:

` + "```nginx" + `
sub_filter '<meta name="generator"' '<!-- generator removed';
sub_filter_once on;
` + "```" + `

Better to handle at WordPress level.`,

			"litespeed": `## LiteSpeed - Hide WP Version

Handle at the WordPress application level. See the WordPress guide.`,

			"plesk": `## Plesk - Hide WP Version

Use the WordPress Toolkit in Plesk:
1. Go to **WordPress** > select your installation
2. Enable **Security** hardening options`,

			"cpanel": `## cPanel - Hide WP Version

Handle at the WordPress level. See the WordPress guide.`,

			"wordpress": `## WordPress - Hide Version

Add to your theme's ` + "`" + `functions.php` + "`" + ` or a custom plugin:

` + "```php" + `
// Remove generator meta tag
remove_action('wp_head', 'wp_generator');

// Remove version from RSS feeds
add_filter('the_generator', '__return_empty_string');

// Remove version from scripts and styles
function remove_wp_version_strings($src) {
    global $wp_version;
    parse_str(parse_url($src, PHP_URL_QUERY), $query);
    if (!empty($query['ver']) && $query['ver'] === $wp_version) {
        $src = remove_query_arg('ver', $src);
    }
    return $src;
}
add_filter('script_loader_src', 'remove_wp_version_strings');
add_filter('style_loader_src', 'remove_wp_version_strings');
` + "```" + `

Also delete ` + "`" + `readme.html` + "`" + ` from the WordPress root directory.`,
		},
	}

	// -------------------------------------------------------------------------
	// 14. wp-login.php
	// -------------------------------------------------------------------------
	RemediationDB["WP Login Page Exposure"] = RemediationGuide{
		CheckName:    "WP Login Page Exposure",
		Title:        "Protect WordPress Login Page",
		Description:  "An exposed login page is the primary target for brute force attacks against WordPress sites.",
		Priority:     "high",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Protect WP Login

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`" + `(http.request.uri.path contains "/wp-login.php") and not ip.src in {YOUR_IP}` + "`" + `
   - **Action**: Block or JS Challenge
3. Enable **Bot Fight Mode** under Security > Bots`,

			"apache": `## Apache - Protect WP Login

**Option 1: IP restriction**

` + "```apache" + `
<Files wp-login.php>
    Require ip 192.168.1.0/24
    Require ip YOUR.OFFICE.IP
</Files>
` + "```" + `

**Option 2: HTTP Auth**

` + "```apache" + `
<Files wp-login.php>
    AuthName "Admin Area"
    AuthType Basic
    AuthUserFile /path/to/.htpasswd
    Require valid-user
</Files>
` + "```",

			"nginx": `## Nginx - Protect WP Login

` + "```nginx" + `
location = /wp-login.php {
    allow 192.168.1.0/24;
    allow YOUR.OFFICE.IP;
    deny all;

    # Or use basic auth:
    # auth_basic "Admin Area";
    # auth_basic_user_file /etc/nginx/.htpasswd;

    include fastcgi_params;
    fastcgi_pass php;
}
` + "```",

			"litespeed": `## LiteSpeed - Protect WP Login

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<Files wp-login.php>
    Require ip YOUR.OFFICE.IP
</Files>
` + "```",

			"plesk": `## Plesk - Protect WP Login

Use **WordPress Toolkit** > **Security** > restrict login access.

Or add to Apache directives:

` + "```apache" + `
<Files wp-login.php>
    Require ip YOUR.OFFICE.IP
</Files>
` + "```",

			"cpanel": `## cPanel - Protect WP Login

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<Files wp-login.php>
    Require ip YOUR.OFFICE.IP
</Files>
` + "```",

			"wordpress": `## WordPress - Protect Login Page

**Option 1: Change login URL (Recommended)**

Install **WPS Hide Login** plugin:
1. Go to **Plugins** > **Add New** > search "WPS Hide Login"
2. Activate and set a custom login URL (e.g., ` + "`" + `/my-secret-login` + "`" + `)

**Option 2: Limit login attempts**

Install **Limit Login Attempts Reloaded**:
- Blocks IPs after failed attempts
- Configurable lockout duration

**Option 3: Two-Factor Authentication**

Install **WP 2FA** or **Google Authenticator** plugin.`,
		},
	}

	// -------------------------------------------------------------------------
	// 15. XML-RPC
	// -------------------------------------------------------------------------
	RemediationDB["WP XML-RPC Exposure"] = RemediationGuide{
		CheckName:    "WP XML-RPC Exposure",
		Title:        "Disable WordPress XML-RPC",
		Description:  "XML-RPC is exploited for brute force attacks, DDoS amplification, and pingback abuse.",
		Priority:     "critical",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block XML-RPC

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`" + `(http.request.uri.path contains "/xmlrpc.php")` + "`" + `
   - **Action**: Block`,

			"apache": `## Apache - Disable XML-RPC

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<Files xmlrpc.php>
    Require all denied
</Files>
` + "```",

			"nginx": `## Nginx - Disable XML-RPC

` + "```nginx" + `
location = /xmlrpc.php {
    deny all;
    return 403;
}
` + "```",

			"litespeed": `## LiteSpeed - Disable XML-RPC

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<Files xmlrpc.php>
    Require all denied
</Files>
` + "```",

			"plesk": `## Plesk - Disable XML-RPC

Use **WordPress Toolkit** > **Security** > disable XML-RPC.

Or add to Apache directives:

` + "```apache" + `
<Files xmlrpc.php>
    Require all denied
</Files>
` + "```",

			"cpanel": `## cPanel - Disable XML-RPC

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<Files xmlrpc.php>
    Require all denied
</Files>
` + "```",

			"wordpress": `## WordPress - Disable XML-RPC

**Option 1: Plugin (Recommended)**

Install **Disable XML-RPC** plugin.

**Option 2: functions.php**

` + "```php" + `
add_filter('xmlrpc_enabled', '__return_false');

// Also remove pingback header
add_filter('wp_headers', function($headers) {
    unset($headers['X-Pingback']);
    return $headers;
});
` + "```" + `

> **Note**: If you use the WordPress mobile app or Jetpack, you may need XML-RPC enabled. Consider using **Disable XML-RPC Pingback** instead.`,
		},
	}

	// -------------------------------------------------------------------------
	// 16. Directory Listing
	// -------------------------------------------------------------------------
	RemediationDB["Admin Panel Exposure"] = RemediationGuide{
		CheckName:    "Admin Panel Exposure",
		Title:        "Disable Directory Listing",
		Description:  "Directory listing exposes file structure and sensitive files to attackers.",
		Priority:     "high",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Directory listing is a server-side configuration. Cloudflare cannot prevent it directly. Configure at the origin server level.`,

			"apache": `## Apache - Disable Directory Listing

` + "```apache" + `
Options -Indexes
` + "```" + `

Add to ` + "`" + `.htaccess` + "`" + ` or in the ` + "`" + `<Directory>` + "`" + ` block of your virtual host.`,

			"nginx": `## Nginx - Disable Directory Listing

` + "```nginx" + `
autoindex off;
` + "```" + `

This is off by default in Nginx. Check that no location block has ` + "`" + `autoindex on` + "`" + `.`,

			"litespeed": `## LiteSpeed - Disable Directory Listing

Add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
Options -Indexes
` + "```",

			"plesk": `## Plesk - Disable Directory Listing

1. Go to **Domains** > your domain > **Apache & nginx Settings**
2. Uncheck **Indexes** in the Options section
3. Or add: ` + "`" + `Options -Indexes` + "`",

			"cpanel": `## cPanel - Disable Directory Listing

1. Go to **Advanced** > **Indexes**
2. Select **No Indexing** for your directories
3. Or edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
Options -Indexes
` + "```",

			"wordpress": `## WordPress - Disable Directory Listing

Add to ` + "`" + `.htaccess` + "`" + ` in WordPress root:

` + "```apache" + `
Options -Indexes
` + "```" + `

WordPress usually includes this by default.`,
		},
	}

	// -------------------------------------------------------------------------
	// 17. Robots.txt
	// -------------------------------------------------------------------------
	RemediationDB["Robots.txt Exposure"] = RemediationGuide{
		CheckName:    "Robots.txt Exposure",
		Title:        "Robots.txt Best Practices",
		Description:  "robots.txt should guide search engines without revealing sensitive directory paths.",
		Priority:     "low",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

robots.txt is served from your origin server. Configure it there.`,

			"apache": `## robots.txt Best Practices

Create/edit ` + "`" + `robots.txt` + "`" + ` in your document root:

` + "```" + `
User-agent: *
Disallow: /admin/
Disallow: /private/
Disallow: /tmp/

Sitemap: https://yourdomain.com/sitemap.xml
` + "```" + `

**Do NOT** list sensitive paths you want hidden - attackers read robots.txt too!`,

			"nginx": `## robots.txt Best Practices

Place ` + "`" + `robots.txt` + "`" + ` in your document root with:

` + "```" + `
User-agent: *
Disallow: /admin/
Disallow: /private/
Sitemap: https://yourdomain.com/sitemap.xml
` + "```" + `

Never list sensitive paths you want to keep secret.`,

			"litespeed": `## robots.txt Best Practices

Same as Apache - create ` + "`" + `robots.txt` + "`" + ` in your document root. Avoid listing truly sensitive paths.`,

			"plesk": `## Plesk - robots.txt

1. Go to **Domains** > your domain > **SEO Toolkit** (if available)
2. Or create ` + "`" + `robots.txt` + "`" + ` manually in the document root`,

			"cpanel": `## cPanel - robots.txt

1. Go to **File Manager** > document root
2. Create/edit ` + "`" + `robots.txt` + "`" + `
3. Avoid listing sensitive directory paths`,

			"wordpress": `## WordPress - robots.txt

WordPress auto-generates a virtual ` + "`" + `robots.txt` + "`" + `. To customize:

1. Install **Yoast SEO** plugin
2. Go to **SEO** > **Tools** > **File Editor** > **robots.txt**
3. Or create a physical ` + "`" + `robots.txt` + "`" + ` in the WP root directory`,
		},
	}

	// -------------------------------------------------------------------------
	// 18. Cache Headers
	// -------------------------------------------------------------------------
	RemediationDB["Cache Headers"] = RemediationGuide{
		CheckName:    "Cache Headers",
		Title:        "Configure Cache Headers",
		Description:  "Proper cache headers improve performance and reduce server load while ensuring fresh content delivery.",
		Priority:     "medium",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Cache Configuration

1. Go to **Caching** > **Configuration**
2. Set **Browser Cache TTL** to **Respect Existing Headers** or a specific duration
3. Create **Page Rules** for specific cache behavior:
   - Static assets: Cache Level = Cache Everything, Edge TTL = 1 month
   - API endpoints: Cache Level = Bypass`,

			"apache": `## Apache - Cache Headers

` + "```apache" + `
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/svg+xml "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType text/html "access plus 0 seconds"
</IfModule>

<IfModule mod_headers.c>
    <FilesMatch "\.(ico|jpg|jpeg|png|gif|svg|css|js|woff2)$">
        Header set Cache-Control "public, max-age=31536000, immutable"
    </FilesMatch>
    <FilesMatch "\.(html|php)$">
        Header set Cache-Control "no-cache, must-revalidate"
    </FilesMatch>
</IfModule>
` + "```",

			"nginx": `## Nginx - Cache Headers

` + "```nginx" + `
location ~* \.(ico|jpg|jpeg|png|gif|svg|css|js|woff2)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}

location ~* \.(html|php)$ {
    add_header Cache-Control "no-cache, must-revalidate";
}
` + "```",

			"litespeed": `## LiteSpeed - Cache Headers

LiteSpeed Cache plugin (for WordPress) handles this automatically.

For manual configuration, add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
</IfModule>
` + "```",

			"plesk": `## Plesk - Cache Headers

In **Apache & nginx Settings**:

` + "```apache" + `
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
</IfModule>
` + "```",

			"cpanel": `## cPanel - Cache Headers

Edit ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
</IfModule>
` + "```",

			"wordpress": `## WordPress - Cache Headers

**Option 1: Caching plugin (Recommended)**

Install **WP Super Cache**, **W3 Total Cache**, or **LiteSpeed Cache**.

**Option 2: .htaccess**

` + "```apache" + `
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType text/html "access plus 0 seconds"
</IfModule>
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// 19. Brotli Compression
	// -------------------------------------------------------------------------
	RemediationDB["Brotli Compression"] = RemediationGuide{
		CheckName:    "Brotli Compression",
		Title:        "Enable Brotli Compression",
		Description:  "Brotli offers 15-25% better compression than gzip, significantly improving page load speed.",
		Priority:     "medium",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Enable Brotli

1. Go to **Speed** > **Optimization** > **Content Optimization**
2. Enable **Brotli**

> Cloudflare handles Brotli compression at the edge automatically.`,

			"apache": `## Apache - Enable Brotli

Ensure ` + "`" + `mod_brotli` + "`" + ` is installed (Apache 2.4.26+):

` + "```bash" + `
sudo a2enmod brotli
` + "```" + `

Add to your config:

` + "```apache" + `
<IfModule mod_brotli.c>
    AddOutputFilterByType BROTLI_COMPRESS text/html text/plain text/xml text/css
    AddOutputFilterByType BROTLI_COMPRESS application/javascript application/json
    AddOutputFilterByType BROTLI_COMPRESS image/svg+xml application/xml
    BrotliCompressionQuality 6
</IfModule>
` + "```",

			"nginx": `## Nginx - Enable Brotli

Install ` + "`" + `ngx_brotli` + "`" + ` module, then add:

` + "```nginx" + `
brotli on;
brotli_comp_level 6;
brotli_types text/plain text/css application/json application/javascript
             text/xml application/xml image/svg+xml;
` + "```",

			"litespeed": `## LiteSpeed - Enable Brotli

1. In **LiteSpeed Web Admin** > **Configuration** > **Server** > **Tuning**
2. Set **Enable Brotli Compression**: Yes
3. Set **Brotli Compression Level**: 6

Or add to ` + "`" + `.htaccess` + "`" + `:

` + "```apache" + `
<IfModule mod_deflate.c>
    # LiteSpeed handles brotli automatically when enabled
    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css application/javascript
</IfModule>
` + "```",

			"plesk": `## Plesk - Enable Brotli

1. SSH into the server
2. Install brotli module for your web server
3. Configure in Apache/Nginx settings (see respective guides)`,

			"cpanel": `## cPanel - Enable Brotli

1. Check with your hosting provider if Brotli is available
2. If using Apache, the module needs to be compiled and enabled by root
3. As a fallback, ensure gzip is enabled via ` + "`" + `Optimize Website` + "`" + ` in cPanel`,
		},
	}

	// -------------------------------------------------------------------------
	// 20. Rate Limiting
	// -------------------------------------------------------------------------
	RemediationDB["Rate Limiting"] = RemediationGuide{
		CheckName:    "Rate Limiting",
		Title:        "Configure Rate Limiting",
		Description:  "Rate limiting protects against brute force attacks, DDoS, and API abuse by limiting request frequency.",
		Priority:     "high",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Rate Limiting

1. Go to **Security** > **WAF** > **Rate limiting rules**
2. Create a rule:
   - **Expression**: ` + "`" + `(http.request.uri.path contains "/wp-login.php")` + "`" + `
   - **Rate**: 5 requests per 10 seconds
   - **Action**: Block for 1 hour
3. For API endpoints:
   - **Rate**: 100 requests per minute
   - **Action**: JS Challenge

Also enable **Bot Fight Mode** under **Security** > **Bots**.`,

			"apache": `## Apache - Rate Limiting

Using ` + "`" + `mod_evasive` + "`" + `:

` + "```bash" + `
sudo apt install libapache2-mod-evasive
sudo a2enmod evasive
` + "```" + `

Configure ` + "`" + `/etc/apache2/mods-enabled/evasive.conf` + "`" + `:

` + "```apache" + `
<IfModule mod_evasive20.c>
    DOSHashTableSize 3097
    DOSPageCount 5
    DOSSiteCount 50
    DOSPageInterval 1
    DOSSiteInterval 1
    DOSBlockingPeriod 600
</IfModule>
` + "```",

			"nginx": `## Nginx - Rate Limiting

` + "```nginx" + `
# Define rate limit zones
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

server {
    # Apply to login page
    location = /wp-login.php {
        limit_req zone=login burst=3 nodelay;
        # ... existing config
    }

    # Apply to API
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        # ... existing config
    }
}
` + "```",

			"litespeed": `## LiteSpeed - Rate Limiting

LiteSpeed has built-in anti-DDoS:

1. In **LiteSpeed Web Admin** > **Configuration** > **Server** > **Security**
2. Set:
   - **Per Client Throttling**: Bandwidth and request limits
   - **Static Requests/second**: 40
   - **Dynamic Requests/second**: 5

Or use ` + "`" + `.htaccess` + "`" + ` with mod_evasive equivalent settings.`,

			"plesk": `## Plesk - Rate Limiting

1. Install **Fail2Ban** via Plesk Extensions
2. Configure jails for your services
3. Or use the web server-level configuration (see Apache/Nginx guides)`,

			"cpanel": `## cPanel - Rate Limiting

1. Use **ModSecurity** (available in cPanel):
   - Go to **Security** > **ModSecurity**
   - Enable with OWASP ruleset
2. Install **CSF (ConfigServer Security & Firewall)**:
   - Provides connection rate limiting and flood protection
3. For WordPress, install **Wordfence** or **Limit Login Attempts** plugin`,

			"wordpress": `## WordPress - Rate Limiting

**Option 1: Security Plugin**

Install **Wordfence** or **Sucuri Security**:
- Built-in rate limiting
- Brute force protection
- Login attempt limits

**Option 2: Limit Login Attempts**

Install **Limit Login Attempts Reloaded** plugin:
1. Set max retries: 3
2. Lockout duration: 20 minutes
3. After lockouts: 24 hours

**Option 3: Application-level** (functions.php)

` + "```php" + `
// Basic throttle for REST API
add_filter('rest_authentication_errors', function($result) {
    $rate_key = 'rest_rate_' . $_SERVER['REMOTE_ADDR'];
    $count = get_transient($rate_key) ?: 0;
    if ($count > 100) {
        return new WP_Error('rate_limited', 'Too many requests', array('status' => 429));
    }
    set_transient($rate_key, $count + 1, 60);
    return $result;
});
` + "```",
		},
	}

	// -------------------------------------------------------------------------
	// Additional remediations for common checks
	// -------------------------------------------------------------------------

	RemediationDB["X-Content-Type-Options"] = RemediationGuide{
		CheckName:    "X-Content-Type-Options",
		Title:        "Set X-Content-Type-Options Header",
		Description:  "Prevents browsers from MIME-sniffing, which can lead to XSS attacks via uploaded files.",
		Priority:     "medium",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - X-Content-Type-Options

1. Go to **Rules** > **Transform Rules** > **Modify Response Header**
2. Add: ` + "`" + `X-Content-Type-Options: nosniff` + "`",

			"apache": `## Apache

` + "```apache" + `
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
</IfModule>
` + "```",

			"nginx": `## Nginx

` + "```nginx" + `
add_header X-Content-Type-Options "nosniff" always;
` + "```",

			"litespeed": `## LiteSpeed

` + "```apache" + `
Header always set X-Content-Type-Options "nosniff"
` + "```",

			"plesk": `## Plesk

Add to Apache directives: ` + "`" + `Header always set X-Content-Type-Options "nosniff"` + "`",

			"cpanel": `## cPanel

Edit ` + "`" + `.htaccess` + "`" + `: ` + "`" + `Header always set X-Content-Type-Options "nosniff"` + "`",

			"wordpress": `## WordPress

` + "```php" + `
add_action('send_headers', function() {
    header('X-Content-Type-Options: nosniff');
});
` + "```",
		},
	}

	RemediationDB["X-XSS-Protection"] = RemediationGuide{
		CheckName:    "X-XSS-Protection",
		Title:        "Set X-XSS-Protection Header",
		Description:  "Legacy browser XSS filter. Modern browsers rely on CSP, but this provides defense in depth.",
		Priority:     "low",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Add via Transform Rules: ` + "`" + `X-XSS-Protection: 1; mode=block` + "`",

			"apache": `## Apache

` + "```apache" + `
Header always set X-XSS-Protection "1; mode=block"
` + "```",

			"nginx": `## Nginx

` + "```nginx" + `
add_header X-XSS-Protection "1; mode=block" always;
` + "```",

			"litespeed": `## LiteSpeed

` + "```apache" + `
Header always set X-XSS-Protection "1; mode=block"
` + "```",

			"plesk": `## Plesk

Add to Apache directives: ` + "`" + `Header always set X-XSS-Protection "1; mode=block"` + "`",

			"cpanel": `## cPanel

Edit ` + "`" + `.htaccess` + "`" + `: ` + "`" + `Header always set X-XSS-Protection "1; mode=block"` + "`",

			"wordpress": `## WordPress

` + "```php" + `
add_action('send_headers', function() {
    header('X-XSS-Protection: 1; mode=block');
});
` + "```",
		},
	}

	RemediationDB["Referrer-Policy"] = RemediationGuide{
		CheckName:    "Referrer-Policy",
		Title:        "Set Referrer-Policy Header",
		Description:  "Controls how much referrer information is sent with requests, protecting user privacy.",
		Priority:     "medium",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Add via Transform Rules: ` + "`" + `Referrer-Policy: strict-origin-when-cross-origin` + "`",

			"apache": `## Apache

` + "```apache" + `
Header always set Referrer-Policy "strict-origin-when-cross-origin"
` + "```",

			"nginx": `## Nginx

` + "```nginx" + `
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
` + "```",

			"litespeed": `## LiteSpeed

` + "```apache" + `
Header always set Referrer-Policy "strict-origin-when-cross-origin"
` + "```",

			"plesk": `## Plesk

Add to Apache directives: ` + "`" + `Header always set Referrer-Policy "strict-origin-when-cross-origin"` + "`",

			"cpanel": `## cPanel

Edit ` + "`" + `.htaccess` + "`" + `: ` + "`" + `Header always set Referrer-Policy "strict-origin-when-cross-origin"` + "`",

			"wordpress": `## WordPress

` + "```php" + `
add_action('send_headers', function() {
    header('Referrer-Policy: strict-origin-when-cross-origin');
});
` + "```",
		},
	}

	RemediationDB["WP REST API User Enumeration"] = RemediationGuide{
		CheckName:    "WP REST API User Enumeration",
		Title:        "Block WordPress User Enumeration via REST API",
		Description:  "The REST API can expose usernames, enabling targeted brute force attacks.",
		Priority:     "high",
		TimeEstimate: "10 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block WP User Enumeration

1. Go to **Security** > **WAF** > **Custom Rules**
2. Create a rule:
   - **Expression**: ` + "`" + `(http.request.uri.path contains "/wp-json/wp/v2/users")` + "`" + `
   - **Action**: Block`,

			"apache": `## Apache - Block User Enumeration

` + "```apache" + `
RewriteEngine On
RewriteRule ^wp-json/wp/v2/users - [F,L]
` + "```",

			"nginx": `## Nginx - Block User Enumeration

` + "```nginx" + `
location ~* /wp-json/wp/v2/users {
    deny all;
    return 403;
}
` + "```",

			"litespeed": `## LiteSpeed

` + "```apache" + `
RewriteEngine On
RewriteRule ^wp-json/wp/v2/users - [F,L]
` + "```",

			"plesk": `## Plesk

Add to Apache directives:
` + "```apache" + `
RewriteRule ^wp-json/wp/v2/users - [F,L]
` + "```",

			"cpanel": `## cPanel

Edit ` + "`" + `.htaccess` + "`" + `:
` + "```apache" + `
RewriteEngine On
RewriteRule ^wp-json/wp/v2/users - [F,L]
` + "```",

			"wordpress": `## WordPress - Block User Enumeration

**Option 1: Plugin**

Install **Disable REST API** or **Disable WP REST API** plugin.

**Option 2: functions.php**

` + "```php" + `
// Restrict users endpoint to authenticated users only
add_filter('rest_endpoints', function($endpoints) {
    if (isset($endpoints['/wp/v2/users'])) {
        unset($endpoints['/wp/v2/users']);
    }
    if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
        unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
    }
    return $endpoints;
});
` + "```",
		},
	}

	RemediationDB["WP Readme/License Exposure"] = RemediationGuide{
		CheckName:    "WP Readme/License Exposure",
		Title:        "Remove WordPress Readme and License Files",
		Description:  "These files reveal that the site runs WordPress and may expose the exact version.",
		Priority:     "low",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Block Readme/License

1. Go to **Security** > **WAF** > **Custom Rules**
2. Block paths: ` + "`" + `(http.request.uri.path eq "/readme.html") or (http.request.uri.path eq "/license.txt")` + "`",

			"apache": `## Apache

` + "```apache" + `
<FilesMatch "^(readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>
` + "```",

			"nginx": `## Nginx

` + "```nginx" + `
location ~* ^/(readme\.html|license\.txt)$ {
    deny all;
    return 404;
}
` + "```",

			"litespeed": `## LiteSpeed

` + "```apache" + `
<FilesMatch "^(readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>
` + "```",

			"plesk": `## Plesk

Delete the files or add to Apache directives:
` + "```apache" + `
<FilesMatch "^(readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>
` + "```",

			"cpanel": `## cPanel

1. Go to **File Manager**
2. Delete ` + "`" + `readme.html` + "`" + ` and ` + "`" + `license.txt` + "`" + ` from WordPress root
3. Or block via ` + "`" + `.htaccess` + "`",

			"wordpress": `## WordPress

1. **Delete the files** from your WordPress root:
   - ` + "`" + `readme.html` + "`" + `
   - ` + "`" + `license.txt` + "`" + `

> **Note**: These files may be recreated after WordPress updates. Add a post-update script or use ` + "`" + `.htaccess` + "`" + ` to block access permanently.`,
		},
	}

	RemediationDB["WP Debug Mode"] = RemediationGuide{
		CheckName:    "WP Debug Mode",
		Title:        "Disable WordPress Debug Mode in Production",
		Description:  "Debug mode exposes PHP errors, file paths, and potentially sensitive data to visitors.",
		Priority:     "critical",
		TimeEstimate: "5 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

Debug mode is a WordPress/PHP configuration. Fix at the application level.`,

			"apache": `## Apache - Block debug.log

` + "```apache" + `
<Files debug.log>
    Require all denied
</Files>
` + "```",

			"nginx": `## Nginx - Block debug.log

` + "```nginx" + `
location ~* /debug\.log$ {
    deny all;
    return 404;
}
` + "```",

			"litespeed": `## LiteSpeed - Block debug.log

` + "```apache" + `
<Files debug.log>
    Require all denied
</Files>
` + "```",

			"plesk": `## Plesk

1. Use WordPress Toolkit to disable debug mode
2. Or edit wp-config.php directly`,

			"cpanel": `## cPanel

Edit ` + "`" + `wp-config.php` + "`" + ` via File Manager (see WordPress guide).`,

			"wordpress": `## WordPress - Disable Debug Mode

Edit ` + "`" + `wp-config.php` + "`" + `:

` + "```php" + `
// Disable debug mode in production
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);

// If you need logging without display:
// define('WP_DEBUG', true);
// define('WP_DEBUG_LOG', true);
// define('WP_DEBUG_DISPLAY', false);
` + "```" + `

Also delete the existing debug.log:

` + "```bash" + `
rm /path/to/wordpress/wp-content/debug.log
` + "```" + `

Block access via ` + "`" + `.htaccess` + "`" + ` in ` + "`" + `wp-content/` + "`" + `:

` + "```apache" + `
<Files debug.log>
    Require all denied
</Files>
` + "```",
		},
	}

	RemediationDB["HTTPS Enabled"] = RemediationGuide{
		CheckName:    "HTTPS Enabled",
		Title:        "Enable HTTPS with SSL/TLS Certificate",
		Description:  "HTTPS encrypts all data between the browser and server, preventing eavesdropping and tampering.",
		Priority:     "critical",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare - Enable HTTPS

1. Add your site to Cloudflare
2. Cloudflare provides a **free Universal SSL certificate** automatically
3. Go to **SSL/TLS** and set mode to **Full (Strict)**
4. Enable **Always Use HTTPS**`,

			"apache": `## Apache - Enable HTTPS with Let's Encrypt

` + "```bash" + `
sudo apt install certbot python3-certbot-apache
sudo certbot --apache -d yourdomain.com -d www.yourdomain.com
` + "```" + `

Certbot will automatically configure Apache and set up auto-renewal.`,

			"nginx": `## Nginx - Enable HTTPS with Let's Encrypt

` + "```bash" + `
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
` + "```",

			"litespeed": `## LiteSpeed - Enable HTTPS

1. In **LiteSpeed Web Admin** > **Listeners** > Add HTTPS listener on port 443
2. Use Let's Encrypt: ` + "`" + `certbot certonly --webroot -w /path/to/webroot -d yourdomain.com` + "`" + `
3. Configure the certificate path in the listener settings`,

			"plesk": `## Plesk - Enable HTTPS

1. Go to **Domains** > your domain > **SSL/TLS Certificates**
2. Click **Install** > **Let's Encrypt**
3. Check **Redirect from HTTP to HTTPS**`,

			"cpanel": `## cPanel - Enable HTTPS

1. Go to **Security** > **SSL/TLS**
2. Use **AutoSSL** (free) or install your own certificate
3. Enable **Force HTTPS** in domain settings`,
		},
	}

	RemediationDB["CORS Configuration"] = RemediationGuide{
		CheckName:    "CORS Configuration",
		Title:        "Configure CORS Properly",
		Description:  "Misconfigured CORS can allow unauthorized cross-origin access to your API and user data.",
		Priority:     "high",
		TimeEstimate: "15 minutes",
		Guides: map[string]string{
			"cloudflare": `## Cloudflare

CORS is typically configured at the origin server level. Use Transform Rules to add/modify CORS headers if needed.`,

			"apache": `## Apache - CORS Configuration

` + "```apache" + `
<IfModule mod_headers.c>
    # Allow specific origins only (never use *)
    SetEnvIf Origin "^https://(www\.)?yourdomain\.com$" ORIGIN=$0
    Header always set Access-Control-Allow-Origin "%{ORIGIN}e" env=ORIGIN
    Header always set Access-Control-Allow-Methods "GET, POST, OPTIONS"
    Header always set Access-Control-Allow-Headers "Content-Type, Authorization"
    Header always set Access-Control-Max-Age "3600"
</IfModule>
` + "```",

			"nginx": `## Nginx - CORS Configuration

` + "```nginx" + `
location /api/ {
    if ($http_origin ~* "^https://(www\.)?yourdomain\.com$") {
        add_header Access-Control-Allow-Origin $http_origin always;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
        add_header Access-Control-Max-Age 3600 always;
    }

    if ($request_method = OPTIONS) {
        return 204;
    }
}
` + "```",

			"litespeed": `## LiteSpeed

Use the same ` + "`" + `.htaccess` + "`" + ` directives as Apache.`,

			"plesk": `## Plesk

Configure in Apache/Nginx settings for your domain.`,

			"cpanel": `## cPanel

Edit ` + "`" + `.htaccess` + "`" + ` with proper CORS headers (see Apache guide).`,

			"wordpress": `## WordPress - CORS

` + "```php" + `
add_action('init', function() {
    $allowed_origins = ['https://yourdomain.com', 'https://www.yourdomain.com'];
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if (in_array($origin, $allowed_origins)) {
        header("Access-Control-Allow-Origin: $origin");
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
        header("Access-Control-Allow-Headers: Content-Type, Authorization");
    }
});
` + "```",
		},
	}
}
