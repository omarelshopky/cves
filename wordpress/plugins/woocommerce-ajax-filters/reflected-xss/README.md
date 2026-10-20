# Advanced AJAX Product Filters <= 3.2.0.3 - Unauthenticated Reflected Cross-Site Scripting

> - https://patchstack.com/database/wordpress/plugin/woocommerce-ajax-filters/vulnerability/wordpress-advanced-ajax-product-filters-plugin-3-2-0-3-cross-site-scripting-xss-vulnerability
> - https://www.cve.org/CVERecord?id=CVE-2026-66439

## Timeline

- 2/7/2026 - Submission to Wordfence
- 2/7/2026 - Wordfence set the submission as Duplicate
- 4/8/2026 - Patchstack published the primary entry under CVE-2026-16296

## Software Details

| Key              | Value                                                  |
| ---------------- | ------------------------------------------------------ |
| Software Name    | Advanced AJAX Product Filters                          |
| Software Slug    | woocommerce-ajax-filters                               |
| Software URL     | https://wordpress.org/plugins/woocommerce-ajax-filters |
| Affected Version | <= 3.2.0.3                                             |
## Description

An unauthenticated Reflected Cross-Site Scripting vulnerability exists in the Advanced AJAX Product Filters WordPress plugin, in its WPBakery Page Builder compatibility module (includes/compatibility/js_composer.php). On every front-end page, the module's `custom_js()` handler — hooked to `wp_footer` — emits an inline `<script>` block that reflects the current filter query string into a JavaScript string literal with no escaping: `data.brfilter = "<?php echo $data['fullline']; ?>";`

`$data['fullline']` is derived directly from the filters GET parameter. `BeRocket_url_parse_page::parse_get_filter_line()` reads `$_GET['filters']` and only round-trips it through `urlencode()`/`urldecode()`, which preserves the characters (", <, >, /) needed to break out of the JavaScript string and the surrounding `<script>` element. Because the value is echoed into the page unescaped, any attacker who can get a victim to load a crafted URL executes arbitrary JavaScript in the victim's browser in the site's origin.

The vulnerable module is loaded whenever the plugin detects WPBakery Page Builder, i.e. when the WPB_VC_VERSION constant is defined (includes/compatibility/include.php). 

## Implications

An unauthenticated attacker can run arbitrary JavaScript in any visitor's browser—including a logged-in admin—via a crafted link, enabling session theft and full admin account takeover.

## Vulnerability Type

Reflected Cross-Site Scripting

## Authentication Level Required

Unauthenticated

## PoC Video

https://github.com/user-attachments/assets/80758013-39fd-47e0-965f-69e3d9da4f53


## References to Affected Code

1. Sink: unescaped reflection of fullline into an inline `<script>` on `wp_footer`. `custom_js()` echoes `$data['fullline']` directly inside a double-quoted JavaScript string with no esc_js()/esc_html().
> https://plugins.trac.wordpress.org/browser/woocommerce-ajax-filters/tags/3.2.0.3/includes/compatibility/js_composer.php#L177
```php
function custom_js() {
    global $berocket_parse_page_obj;
    $data = $berocket_parse_page_obj->get_current();
?><script>
...
function bapf_init_wpbakery_grid_filters() {
    jQuery('.brapf_wpb_replace_grid.vc_grid-container').each(function() {
        var data = jQuery(this).data('vc-grid-settings');
        data.brfilter = "<?php echo $data['fullline']; ?>";   // unescaped reflection of $_GET['filters']
        ...
```

2. Source: fullline is taken from `$_GET['filters']`. `parse_get_filter_line()` reads the request parameter and only performs a urlencode()/urldecode() round-trip, so XSS metacharacters survive intact; the value is stored as fullline.
> https://plugins.trac.wordpress.org/browser/woocommerce-ajax-filters/tags/3.2.0.3/includes/url-parse.php#L817
```php
public function parse_get_filter_line($link = false) {
    ...
    $filter_var = apply_filters('bapf_uparse_parse1_filter_var', 'filters', $this, $link);
    ...
    } elseif( ! empty($_GET[$filter_var]) ) {
        $filter_line = $_GET[$filter_var];         // attacker-controlled
    }
    $filter_line = urlencode($filter_line);
    $filter_line = str_replace('+', urlencode('+'), $filter_line);
    $filter_line = urldecode($filter_line);        // characters restored raw
    return apply_filters('bapf_uparse_parse_get_filter_line_modify', $filter_line, $this, $link);
}
```

> https://plugins.trac.wordpress.org/browser/woocommerce-ajax-filters/tags/3.2.0.3/includes/url-parse.php#L852
```php
$data = array(
    'fullline' => $filter_line,   // used by the sink above
    'filters'  => array()
    ...
```

3. Load gate: the compatibility module is included only when WPBakery is present.
> https://plugins.trac.wordpress.org/browser/woocommerce-ajax-filters/tags/3.2.0.3/includes/compatibility/include.php#L25
```php
'WPBakery' => array(
    'check' => defined( 'WPB_VC_VERSION'),
    'file'  => 'js_composer.php'
),
```

## Remediation

Update the plugin to version 3.2.1 or later.


## Preconditions

1. Setup WordPress enviornment with (PHP v8.2.29, MySQL 8.0.35, and WordPress 7.0)
2. Install and activate WooCommerce and the Advanced AJAX Product Filters plugins.
3. The vulnerable code path lives in the WPBakery compatibility module, which the plugin loads only when it detects WPBakery via `defined('WPB_VC_VERSION')`. WPBakery is a premium plugin, but its presence is detected solely through that constant — so a must-use plugin that defines it reproduces the exact same load path the plugin takes on a real WPBakery install. Create `wp-content/mu-plugins/wpb-stub.php`:
```php
<?php
if ( ! defined( 'WPB_VC_VERSION' ) ) {
    define( 'WPB_VC_VERSION', '7.0' );
}
```

4. Follow the default plugin setup.


## Steps to Reproduce

Visit the following URL and observe the injected JavaScript executed successfully.

```url
http://woocommerce-ajax-filters.local/shop/?filters=%22%3B%7D%3C/script%3E%3Cscript%3Ealert(`3l5h0pky`)%3C/script%3E
```
