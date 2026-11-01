# Writeups

Personal portfolio and technical write-ups covering Linux, cybersecurity (recon, CTF challenges, site analysis), and system administration.

## Build

Requires [Hugo](https://gohugo.io/) (extended build preferred).

```bash
hugo server        # preview (localhost:1313)
hugo                # build static site (public/)
```

## Theme

Custom minimal theme (`themes/basic`) rebuilt after a Jekyll-to-Hugo migration. Key templates in `themes/basic/layouts/_default/`.

## Content notes

- `category` is remapped to taxonomy `section` (`config.toml`) for legacy compatibility.
- Write-ups are in `content/` grouped by topic: `linux/`, `ctf/`, `recon/`, `site-analysis/`.
- Search index (`search.json`) is generated from page metadata.

## Deployment

Site is deployed via GitHub Pages (`https://aayush-lams.github.io/Writeups`). Portfolio hosted at `https://aayush-lamsal.vercel.app`.

## License

MIT License — see `LICENSE` file.
