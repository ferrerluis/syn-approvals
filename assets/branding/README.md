# Syn branding

Current ghost artwork supplied by Luis on 2026-09-08. The app icon is the original
Icon Composer package; the in-app and documentation art uses the smallest export
that preserves the source resolution needed by each surface.

| Surface | Artwork | Source |
| --- | --- | --- |
| README and light-mode app UI | Light ghost icon | 1022px PNG |
| Dark-mode app UI | Dark ghost icon | 1022px PNG |
| Dock, Finder and system identity | Layered ghost icon | `app-icon/Syn.icon` |
| Scalable documents | Standalone ghost mark | SVG |
| macOS menu bar | Existing black template mark | SVG, aspect-fitted to 18 points |

## Original exports

- `app-icon/Syn.icon` is the unmodified Icon Composer package.
- `light/` and `dark/` contain the 1022px Group 12 exports used inside the app.
- `mark/` contains the standalone Group 8 SVG.
- `menu-bar/` keeps the prior monochrome artwork unchanged.

The Syn project's PARA `branding/` collection retains every supplied 1x, 2x, 3x,
SVG and Icon Composer source. Its `archive/` directory preserves superseded sets.

## Appearance and packaging

The light and dark in-app images are separate originals. SwiftUI selects the
matching image for the current color scheme.

The menu artwork is black plus transparency. AppKit treats it as a template and
supplies light, dark and highlighted contrast. The source isn't square, so Syn
aspect-fits it rather than stretching it. Pending requests retain a separate dot
and accessible label.

`scripts/build-macos-app.sh` compiles `Syn.icon` with Xcode's asset compiler. The
result includes `Assets.car` for native appearance-aware rendering and `Syn.icns`
as the compatibility fallback; macOS owns the mask, material and shadow.

The package smoke test compiles the real `SynBranding` code into a relocated
probe app without linking the model, authentication or transport services. It
checks exact packaged resources, the compiled Icon Composer catalog, every
16–1024px compatibility size and the missing-artwork fallback.
