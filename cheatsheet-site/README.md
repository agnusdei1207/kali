# Cheatsheet

A documentation-style site of cheatsheets, methodology, and tools for OSCP preparation. The content structure follows heretek.dev, and the layout is sidebar, body, and table of contents.

- Live: <https://agnusdei1207.github.io/cheatsheet/>
- Repository: <https://github.com/agnusdei1207/cheatsheet>

The GitHub Pages address follows the repository owner account (`agnusdei1207`).

## Structure

| Path | Contents |
|---|---|
| `content/oscp-cheatsheet/` | Site cheatsheet: 20 topics from enumeration to privilege escalation, AD, pivoting, and reporting |
| `content/methodology/` | AD attack methodology, enumeration workflow |
| `content/tools/` | BloodHound and Impacket guides |
| `layouts/` | Site-specific Hugo layouts |
| `assets/` | `css/main.css` (design tokens and layout), `js/site.js` (theme, sidebar, TOC), `js/search.js` (search) |
| `.github/workflows/` | `deploy-pages` build and deploy workflow |

## Deployment

Pushing to the `main` branch runs GitHub Actions (`deploy-pages`), which builds the site with Hugo and deploys it to GitHub Pages. Do not build locally.
