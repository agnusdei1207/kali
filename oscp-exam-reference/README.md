# OSCP Exam Reference

A documentation-style site of cheatsheets, methodology, and tools for OSCP preparation. The content structure follows heretek.dev, and the layout is sidebar, body, and table of contents.

This folder is the source of the static site served at <https://agnusdei1207.github.io/kali/>. It is a separate subtree inside the `kali` repository, kept apart from `docs/cheatsheets/`: this site is a quick reference for moments when you are stuck during the exam, while `docs/cheatsheets/` is the practice ground with tool usage and lab procedures.

- Live: <https://agnusdei1207.github.io/kali/>
- Repository: <https://github.com/agnusdei1207/kali>
- Deployment workflow: repository root `.github/workflows/deploy-pages.yml`

## Structure

| Path | Contents |
|---|---|
| `content/oscp-cheatsheet/` | Site cheatsheet: 20 topics from enumeration to privilege escalation, AD, pivoting, and reporting |
| `content/methodology/` | AD attack methodology, enumeration workflow |
| `content/tools/` | BloodHound and Impacket guides |
| `layouts/` | Site-specific Hugo layouts |
| `assets/` | CSS design tokens and layout, `js/site.js` (theme, sidebar, TOC), `js/search.js` (search) |
| repository root `.github/workflows/` | `deploy-pages` build and deploy workflow |

## Deployment

Pushing to `main` runs the root `deploy-pages` workflow, which builds this folder with Hugo and deploys it to GitHub Pages. Do not build locally.

The site was imported from the former `cheatsheet` repository as a git subtree. That repository is now a redirect stub and is no longer a source; all further edits happen in this folder.
