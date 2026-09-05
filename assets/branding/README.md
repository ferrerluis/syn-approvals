# Syn branding

Original artwork supplied by Luis on 2026-09-04. These files are unchanged apart from descriptive filenames; `color/` corresponds to the supplied `Syn 2` folder and `monochrome/` to `Syn`. The unrelated exploratory artwork under local `output/` is not part of this brand set.

| Surface | Artwork | Size and format |
| --- | --- | --- |
| README and documentation | Color logo | SVG; README displays it at 112 × 112 CSS pixels |
| Mac sidebar / approval header | Color logo | Supplied 423px PNG, displayed at 32 / 36 points |
| Dock, Finder, About and notification identity | Color logo | Generated `Syn.icns`, 16–1024 physical pixels with 8% transparent padding |
| macOS menu bar | Black logo | SVG-backed template image, 18 points; 24-point canvas with a pending-request dot |
| Raster-only consumers | Matching supplied PNG | Choose the smallest export at least as large as the required physical pixels; do not enlarge a small export |

The black artwork is black plus transparency, not a black background. AppKit treats the menu image as a template and supplies the appropriate light/dark/highlight contrast. Pending requests retain a visible indicator and an accessible label; color is not the only status signal. [Apple template-image behavior](https://developer.apple.com/documentation/appkit/nsimage/istemplate).

## Original exports

Each variant has an SVG and four transparent PNGs: 423 × 423 (`1x`), 846 × 846 (`2x`), 1268 × 1268 (`3x`) and 1691 × 1691 (`4x`). Export labels are nominal; use these actual pixel dimensions when selecting a raster.

The black SVG is entirely vector. The color SVG retains the supplied vector silhouette with an embedded 1254 × 1254 texture; it is not an infinitely detailed vector gradient. Preserve that texture and transparency; do not recolor, flatten onto a background, or redraw the mark without a new design decision.

## Build and maintenance

The canonical originals live here. Exact copies of the black SVG and 423px color PNG in `macos/Sources/Syn/Resources/Branding` are the only artwork shipped as Swift package resources. Tests enforce byte-for-byte agreement; unused export sizes are not bundled into the app.

The color SVG remains preferred for browser/documentation use. Native AppKit rendering of this particular embedded SVG texture produced a visible horizontal seam during visual QA, so native color surfaces use the supplied PNGs. This is a format compatibility choice, not a redraw or change to the originals.

`scripts/build-macos-app.sh` packages the resource bundle and uses `scripts/build-branding.swift` plus Apple's `iconutil` to render the app icon at every required resolution from the 1691px color PNG. No raster is upscaled. No network access, authentication, private key or installed-app replacement is involved in asset generation.

The package smoke test compiles the actual `SynBranding` code into a relocated probe app, without linking Syn's model or services. It verifies that lookup returns the packaged artwork, then hides that artwork and checks the safe symbol fallback. Build-tree resources remain present to catch accidental dependencies on SwiftPM's absolute fallback path.

PARA stores the original files and durable brand guidance under the Syn project's `branding` collection. Source code and generated app bundles remain in the repository/build workspace, not in PARA.
