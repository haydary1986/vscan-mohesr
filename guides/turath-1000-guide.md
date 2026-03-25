# دليل الحصول على 1000/1000 - جامعة التراث (uoturath.edu.iq)

## الدرجة الحالية: 893/1000 | الهدف: 1000/1000

### ملخص المشاكل المكتشفة (مرتبة حسب التأثير)

| # | المشكلة | الدرجة الحالية | الهدف | النقاط المفقودة |
|---|---------|---------------|-------|----------------|
| 1 | HSTS max-age = 0 (معطّل) | 100 | 1000 | ~45 نقطة |
| 2 | HTTP Methods خطرة مفتوحة | 75 | 1000 | ~30 نقطة |
| 3 | DMARC مفقود | 0 | 1000 | ~12 نقطة |
| 4 | Permissions-Policy مفقود | 0 | 1000 | ~9 نقاط |
| 5 | لوحة Admin مكشوفة | 125 | 1000 | ~7 نقاط |
| 6 | Rate Limiting معدوم | 250 | 1000 | ~5 نقاط |
| 7 | ملفات حساسة ترجع 403 بدل 404 | 725 | 1000 | ~3 نقاط |
| 8 | WordPress مكشوف | 550 | 1000 | ~3 نقاط |
| 9 | Server header مكشوف | 550 | 1000 | ~3 نقاط |
| 10 | إصدارات تقنيات مكشوفة | 425 | 1000 | ~2 نقاط |
| 11 | SPF بدون -all | 725 | 1000 | ~2 نقاط |
| 12 | شهادة SSL تنتهي بعد 54 يوم | 750 | 1000 | ~2 نقاط |
| 13 | CAA record مفقود | 675 | 1000 | ~1 نقطة |
| 14 | DNSSEC غير مفعل | 650 | 1000 | ~1 نقطة |

---

## المرحلة 1: إعدادات Cloudflare (15 دقيقة)

### 1.1 تفعيل HSTS بشكل صحيح

**المشكلة:** HSTS موجود لكن max-age = 0 (معطّل فعلياً)

1. سجل دخول إلى Cloudflare Dashboard
2. اختر الموقع `uoturath.edu.iq`
3. اذهب إلى **SSL/TLS** → **Edge Certificates**
4. فعّل **Always Use HTTPS** = ON
5. مرر للأسفل وفعّل **HTTP Strict Transport Security (HSTS)**:
   - **Enable HSTS** = ON
   - **Max Age Header** = `12 months (31536000)`
   - **Include subdomains** = ON
   - **Preload** = ON
   - **No-Sniff Header** = ON
6. اضغط **Save**

> ⚠️ **تحذير:** بعد تفعيل HSTS مع preload، لا يمكن التراجع بسهولة. تأكد أن HTTPS يعمل بشكل كامل على جميع الصفحات والنطاقات الفرعية.

**التأثير:** 100 → 1000 (+45 نقطة تقريباً)

---

### 1.2 إعداد Security Headers في Cloudflare

**المشكلة:** Permissions-Policy مفقود

1. في Cloudflare اذهب إلى **Rules** → **Transform Rules**
2. اضغط **Create rule** → **Modify Response Header**
3. اسم القاعدة: `Security Headers`
4. في **When incoming requests match**: اختر **All incoming requests**
5. أضف الترويسات التالية (اختر **Set** لكل واحدة):

| Header Name | Value |
|-------------|-------|
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |

6. اضغط **Deploy**

**التأثير:** Permissions-Policy: 0 → 1000، X-Frame-Options: 900 → 1000، Referrer-Policy: 900 → 1000

---

### 1.3 تفعيل Rate Limiting

1. في Cloudflare اذهب إلى **Security** → **WAF**
2. اضغط **Rate limiting rules** → **Create rule**
3. أنشئ قاعدة:
   - **Rule name:** `Rate Limit All`
   - **When:** URI Path contains `/`
   - **Rate:** `100 requests per 10 seconds`
   - **Action:** `Block` for `60 seconds`
   - **With response type:** Default Cloudflare rate limit page
4. اضغط **Deploy**

> ملاحظة: Cloudflare يرسل ترويسات Rate Limiting تلقائياً عند تفعيل هذه القاعدة.

**التأثير:** Rate Limiting: 250 → 1000

---

### 1.4 إعدادات SSL/TLS

1. في **SSL/TLS** → **Overview**: تأكد أن الوضع **Full (strict)**
2. في **SSL/TLS** → **Edge Certificates**:
   - **Minimum TLS Version** = `TLS 1.2`
   - **TLS 1.3** = ON
   - **Automatic HTTPS Rewrites** = ON
3. في **SSL/TLS** → **Origin Server**:
   - أنشئ **Origin Certificate** من Cloudflare (صلاحية 15 سنة)
   - هذا يحل مشكلة انتهاء الشهادة بعد 54 يوم

**التأثير:** Certificate: 750 → 1000

---

### 1.5 إخفاء Server Header

1. في Cloudflare اذهب إلى **Rules** → **Transform Rules** → **Modify Response Header**
2. عدّل القاعدة الموجودة (Security Headers) أو أنشئ واحدة جديدة
3. أضف:
   - **Header:** `Server` → **Action:** `Remove`

**التأثير:** Server Header: 550 → 1000

---

### 1.6 تفعيل DNSSEC

1. في Cloudflare اذهب إلى **DNS** → **Settings**
2. اضغط **Enable DNSSEC**
3. Cloudflare سيعطيك DS Record
4. أضف DS Record عند مسجّل النطاق (المسجّل العراقي أو أي مسجّل تستخدمه)

**التأثير:** DNSSEC: 650 → 1000

---

## المرحلة 2: إعدادات DNS (10 دقائق)

### 2.1 إضافة DMARC Record

**المشكلة:** لا يوجد DMARC - البريد قابل للانتحال

1. في Cloudflare اذهب إلى **DNS** → **Records**
2. أضف سجل جديد:
   - **Type:** `TXT`
   - **Name:** `_dmarc`
   - **Content:** `v=DMARC1; p=reject; rua=mailto:dmarc@uoturath.edu.iq; ruf=mailto:dmarc@uoturath.edu.iq; sp=reject; adkim=s; aspf=s`
   - **TTL:** Auto
3. اضغط **Save**

**شرح الإعدادات:**
- `p=reject` = رفض الرسائل المزيفة (الأقوى)
- `rua=mailto:...` = إرسال تقارير إلى هذا البريد
- `sp=reject` = نفس السياسة للنطاقات الفرعية
- `adkim=s` = محاذاة صارمة لـ DKIM
- `aspf=s` = محاذاة صارمة لـ SPF

**التأثير:** DMARC: 0 → 1000

---

### 2.2 تقوية SPF Record

**المشكلة:** SPF يستخدم `~all` (soft fail) بدلاً من `-all` (hard fail)

1. في **DNS** → **Records** ابحث عن سجل TXT الذي يبدأ بـ `v=spf1`
2. عدّله وغيّر `~all` إلى `-all`

**مثال:**
```
قبل: v=spf1 include:_spf.google.com ~all
بعد: v=spf1 include:_spf.google.com -all
```

**التأثير:** SPF: 725 → 1000

---

### 2.3 إضافة CAA Record

1. في **DNS** → **Records** أضف:
   - **Type:** `CAA`
   - **Name:** `@`
   - **Tag:** `issue`
   - **CA domain name:** `letsencrypt.org`
2. أضف سجل آخر:
   - **Type:** `CAA`
   - **Name:** `@`
   - **Tag:** `issue`
   - **CA domain name:** `comodoca.com`
3. أضف سجل للإبلاغ:
   - **Type:** `CAA`
   - **Name:** `@`
   - **Tag:** `iodef`
   - **Value:** `mailto:admin@uoturath.edu.iq`

**التأثير:** CAA: 675 → 1000

---

## المرحلة 3: إعدادات سيرفر Plesk (20 دقيقة)

### 3.1 تعطيل HTTP Methods الخطرة

**المشكلة:** TRACE, DELETE, PUT, PATCH كلها مفتوحة

#### الطريقة 1: من Plesk مباشرة

1. سجل دخول إلى **Plesk**
2. اذهب إلى **Domains** → `uoturath.edu.iq` → **Apache & nginx Settings**
3. في قسم **Additional Apache directives** أضف:

```apache
# Disable dangerous HTTP methods
<LimitExcept GET POST HEAD OPTIONS>
    Require all denied
</LimitExcept>

# Disable TRACE specifically
TraceEnable Off
```

4. اضغط **OK** / **Apply**

#### الطريقة 2: عبر .htaccess (إذا لا يوجد وصول لـ Plesk Apache settings)

1. من Plesk اذهب إلى **File Manager**
2. افتح ملف `.htaccess` في المجلد الرئيسي للموقع
3. أضف في البداية:

```apache
# Block dangerous HTTP methods
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(TRACE|DELETE|PUT|PATCH|CONNECT) [NC]
RewriteRule .* - [F,L]
```

**التأثير:** HTTP Methods: 75 → 1000

---

### 3.2 حماية لوحة Admin

**المشكلة:** `/admin/` متاح للجميع

في `.htaccess` أضف:

```apache
# Protect admin area - allow only specific IPs
<IfModule mod_rewrite.c>
RewriteEngine On

# Block direct access to /admin/ except from allowed IPs
RewriteCond %{REQUEST_URI} ^/admin [NC]
RewriteCond %{REMOTE_ADDR} !^YOUR\.OFFICE\.IP\.HERE$
RewriteRule .* - [R=404,L]
</IfModule>
```

> استبدل `YOUR.OFFICE.IP.HERE` بـ IP مكتبك. أو إذا تستخدم WordPress:

```apache
# Protect wp-admin
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteCond %{REQUEST_URI} ^/(wp-admin|admin) [NC]
RewriteCond %{REMOTE_ADDR} !^YOUR\.OFFICE\.IP\.HERE$
RewriteCond %{REQUEST_URI} !^/wp-admin/admin-ajax\.php [NC]
RewriteRule .* - [R=404,L]
</IfModule>
```

**التأثير:** Admin Panel: 125 → 1000

---

### 3.3 إرجاع 404 بدل 403 للملفات الحساسة

**المشكلة:** `.env`, `.git/config`, `.htaccess`, `wp-config.php.bak` ترجع 403 (يؤكد وجودها)

في `.htaccess` أضف:

```apache
# Return 404 instead of 403 for sensitive files (don't confirm they exist)
<IfModule mod_rewrite.c>
RewriteEngine On

# Block access to hidden files and directories
RewriteRule ^\.env$ - [R=404,L]
RewriteRule ^\.git - [R=404,L]
RewriteRule ^\.htaccess$ - [R=404,L]
RewriteRule \.bak$ - [R=404,L]
RewriteRule \.sql$ - [R=404,L]
RewriteRule \.log$ - [R=404,L]
</IfModule>
```

**التأثير:** Directory checks: 725 → 1000

---

### 3.4 إخفاء WordPress وإصدارات التقنيات

**المشكلة:** WordPress مكشوف + إصدارات jQuery مكشوفة

#### في ملف `functions.php` للقالب النشط:

1. من Plesk → **File Manager** → `wp-content/themes/[your-theme]/functions.php`
2. أضف في نهاية الملف:

```php
<?php
// Remove WordPress version from head and feeds
remove_action('wp_head', 'wp_generator');
remove_action('wp_head', 'wlwmanifest_link');
remove_action('wp_head', 'rsd_link');

// Remove version from scripts and styles
function remove_version_from_assets($src) {
    if (strpos($src, 'ver=')) {
        $src = remove_query_arg('ver', $src);
    }
    return $src;
}
add_filter('style_loader_src', 'remove_version_from_assets', 9999);
add_filter('script_loader_src', 'remove_version_from_assets', 9999);

// Remove X-Pingback header
function remove_x_pingback($headers) {
    unset($headers['X-Pingback']);
    return $headers;
}
add_filter('wp_headers', 'remove_x_pingback');

// Disable XML-RPC
add_filter('xmlrpc_enabled', '__return_false');

// Remove WordPress version from RSS
function remove_wp_version_rss() { return ''; }
add_filter('the_generator', 'remove_wp_version_rss');
```

#### في `.htaccess` أضف:

```apache
# Block WordPress detection paths
<IfModule mod_rewrite.c>
RewriteEngine On

# Block access to wp-login.php from non-allowed IPs (optional)
# RewriteCond %{REQUEST_URI} ^/wp-login\.php$ [NC]
# RewriteCond %{REMOTE_ADDR} !^YOUR\.IP\.HERE$
# RewriteRule .* - [R=404,L]

# Block readme.html and license.txt (reveals WordPress)
RewriteRule ^readme\.html$ - [R=404,L]
RewriteRule ^license\.txt$ - [R=404,L]

# Block direct access to wp-content/debug.log
RewriteRule ^wp-content/debug\.log$ - [R=404,L]
</IfModule>
```

**التأثير:** CMS Detection: 550 → 1000, Version Disclosure: 425 → 1000

---

### 3.5 إعدادات إضافية في Plesk

#### تفعيل nginx كـ Reverse Proxy:

1. في Plesk → **Domains** → الموقع → **Apache & nginx Settings**
2. في قسم **Additional nginx directives** أضف:

```nginx
# Hide server tokens
server_tokens off;

# Security headers (as backup if Cloudflare misses them)
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;

# Limit request methods at nginx level
if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$) {
    return 444;
}
```

3. اضغط **OK**

---

## المرحلة 4: التحقق (5 دقائق)

### 4.1 ملف .htaccess الكامل النهائي

```apache
# === Seku Security Hardening for uoturath.edu.iq ===

# Block dangerous HTTP methods
RewriteEngine On
RewriteCond %{REQUEST_METHOD} ^(TRACE|DELETE|PUT|PATCH|CONNECT) [NC]
RewriteRule .* - [F,L]

# Return 404 for sensitive files
RewriteRule ^\.env$ - [R=404,L]
RewriteRule ^\.git - [R=404,L]
RewriteRule ^\.htaccess$ - [R=404,L]
RewriteRule \.bak$ - [R=404,L]
RewriteRule \.sql$ - [R=404,L]
RewriteRule \.log$ - [R=404,L]
RewriteRule ^readme\.html$ - [R=404,L]
RewriteRule ^license\.txt$ - [R=404,L]
RewriteRule ^wp-content/debug\.log$ - [R=404,L]

# Protect admin area
RewriteCond %{REQUEST_URI} ^/(wp-admin|admin) [NC]
RewriteCond %{REMOTE_ADDR} !^ALLOWED\.IP\.HERE$
RewriteCond %{REQUEST_URI} !^/wp-admin/admin-ajax\.php [NC]
RewriteRule .* - [R=404,L]

# Disable directory listing
Options -Indexes

# Disable server signature
ServerSignature Off

# Block XML-RPC
<Files xmlrpc.php>
    Require all denied
</Files>

# Protect wp-config.php
<Files wp-config.php>
    Require all denied
</Files>

# === End Security Hardening ===
```

### 4.2 Checklist النهائي

قبل إعادة الفحص، تأكد من:

- [ ] **Cloudflare:** HSTS مفعل مع max-age=31536000 + includeSubDomains + preload
- [ ] **Cloudflare:** Permissions-Policy header مضاف
- [ ] **Cloudflare:** X-Frame-Options = DENY
- [ ] **Cloudflare:** Referrer-Policy = no-referrer
- [ ] **Cloudflare:** Server header محذوف
- [ ] **Cloudflare:** Rate Limiting rule مفعلة
- [ ] **Cloudflare:** DNSSEC مفعل + DS Record مضاف عند المسجّل
- [ ] **Cloudflare:** Origin Certificate مثبتة (15 سنة)
- [ ] **DNS:** DMARC record مضاف (p=reject)
- [ ] **DNS:** SPF محدّث بـ -all
- [ ] **DNS:** CAA records مضافة
- [ ] **Plesk:** HTTP methods خطرة معطلة
- [ ] **Plesk:** .htaccess محدّث بالقواعد أعلاه
- [ ] **Plesk:** functions.php محدّث (إخفاء WordPress)
- [ ] **Plesk:** nginx directives مضافة
- [ ] انتظر 5 دقائق ليتم تطبيق إعدادات Cloudflare
- [ ] أعد الفحص في Seku

### 4.3 الوقت المتوقع لتطبيق التغييرات

| التغيير | وقت التطبيق |
|---------|------------|
| Cloudflare Headers | فوري - 5 دقائق |
| Cloudflare HSTS | فوري - 5 دقائق |
| DNS Records (DMARC, SPF, CAA) | 5 دقائق - ساعة |
| DNSSEC | 24-48 ساعة (بسبب DS Record) |
| تغييرات .htaccess | فوري |
| تغييرات functions.php | فوري |

### 4.4 النتيجة المتوقعة بعد التطبيق

| الفئة | قبل | بعد |
|-------|-----|-----|
| SSL/TLS | 938 | 1000 |
| Headers | 682 | 1000 |
| Cookies | 1000 | 1000 |
| Server Info | 700 | 1000 |
| Directory | 772 | 1000 |
| Performance | 925 | ~950+ |
| DDoS | 775 | 1000 |
| CORS | 1000 | 1000 |
| HTTP Methods | 500 | 1000 |
| DNS | 512 | 1000 |
| Mixed Content | 1000 | 1000 |
| Info Disclosure | 836 | 1000 |
| **المجموع** | **893** | **~995-1000** |

> **ملاحظة:** Performance يعتمد على سرعة السيرفر وقت الفحص ولا يمكن ضمان 1000 بالضبط، لكن باقي المعايير يجب أن تصل 1000 بعد تطبيق كل الخطوات.
