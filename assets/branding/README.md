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
| Idle macOS menu bar | Ghost-only black template mark | PNG, positioned at the pending mark's lower-left scale |
| Approval-pending macOS menu bar | Ghost with three attention lines | SVG, aspect-fitted to 18 points |

## Original exports

- `app-icon/Syn.icon` is the unmodified Icon Composer package.
- `light/` and `dark/` contain the 1022px Group 12 exports used inside the app.
- `mark/` contains the standalone Group 8 SVG.
- `menu-bar/` contains the new ghost-only idle exports and the prior attention-line
  artwork used for approval pending.

The Syn project's PARA `branding/` collection retains every supplied 1x, 2x, 3x,
SVG and Icon Composer source. Its `archive/` directory preserves superseded sets.

## Appearance and packaging

The light and dark in-app images are separate originals. SwiftUI selects the
matching image for the current color scheme.

The menu artwork is black plus transparency. AppKit treats both states as templates
and supplies light, dark and highlighted contrast. Idle draws only the small ghost
in the same lower-left footprint used by the full pending artwork; pending adds the
three supplied attention lines and an accessible pending label.

`scripts/build-macos-app.sh` compiles `Syn.icon` with Xcode's asset compiler. The
result includes `Assets.car` for native appearance-aware rendering and `Syn.icns`
as the compatibility fallback; macOS owns the mask, material and shadow.

The package smoke test compiles the real `SynBranding` code into a relocated
probe app without linking the model, authentication or transport services. It
checks exact packaged resources, the compiled Icon Composer catalog, every
16–1024px compatibility size and the missing-artwork fallback.
