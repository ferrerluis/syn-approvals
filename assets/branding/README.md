# Syn branding

Current illustrated artwork supplied by Luis on 2026-09-05. Files are unchanged
apart from descriptive filenames. The unrelated exploratory artwork under local
`output/` isn't part of this set.

| Surface | Artwork | Source |
| --- | --- | --- |
| README and light-mode app UI | Light illustrated icon | 1022px PNG |
| Dark-mode app UI | Dark illustrated icon | 1022px PNG |
| Dock | Matching light/dark illustrated icon | Generated ICNS files, 16–1024px |
| Finder and system identity | Light illustrated icon | `Syn.icns` |
| macOS menu bar | Black template mark | SVG, aspect-fitted to 18 points |

## Original exports

- `light/` contains the 1022px and 2044px Group 11 PNG exports.
- `dark/` contains the 1022px and 2044px Group 12 PNG exports.
- `menu-bar/` contains the Group 13 SVG and its 987×1087 and 1974×2174 PNG
  exports.

The supplied 3× and 4× app-icon PNGs are byte-identical designs at larger
resolutions but total roughly 86 MB because of the texture. They aren't committed:
the 2044px sources already exceed macOS's 1024px maximum and generate every
required native size without upscaling.

The Syn project's PARA `branding/` collection retains all 11 supplied originals.
Its `archive/` directory preserves the superseded color and monochrome carabiner
sets.

## Appearance and packaging

The light and dark app images are separate originals. SwiftUI selects the matching
image for the current color scheme. The launch delegate selects the matching ICNS
for the running Dock tile and observes appearance changes. The bundle registers
the light ICNS for Finder and other legacy system surfaces.

The menu artwork is black plus transparency. AppKit treats it as a template and
supplies light, dark and highlighted contrast. The source isn't square, so Syn
aspect-fits it rather than stretching it. Pending requests retain a separate dot
and accessible label.

`scripts/build-macos-app.sh` creates both ICNS files from the 2044px sources.
It adds no outer shadow or extra inset: macOS owns the Dock shadow, while the
rounded-square artwork already owns its full canvas.

The package smoke test compiles the real `SynBranding` code into a relocated
probe app without linking the model, authentication or transport services. It
checks exact packaged resources, both appearance mappings, every 16–1024px icon
size and the missing-artwork fallback.
