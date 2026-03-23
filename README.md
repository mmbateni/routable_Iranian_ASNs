# Finding Routable Iranian ASNs
## Three Ground-Truth Approaches in R

---

## Quickstart

```r
source("run_all.R")
results <- run_all(bgp_only = TRUE, expand_neighbours = FALSE)
```

This runs Approach 2 (BGP table scan) with no API key required. It discovers routable Iranian ASNs using a curated set of known seed ASNs plus DNS resolution of well-known Iranian domains. Results are returned as a named list and written to `merged_routable_asns.json`.

To get a flat data frame and save to CSV:

```r
df <- results_to_df(results)
write.csv(df, "iranian_routable_asns.csv", row.names = FALSE)
```

---

## The Problem

Iran has roughly 840 registered Autonomous System Numbers (ASNs). Registration does not equal reachability. A registered ASN might announce prefixes that no global BGP peer propagates further, announce RFC 1918 or other non-routable (bogon) space, exist entirely on paper with no active routing infrastructure, or be reachable from within Iran but unreachable from outside.

The only reliable source of truth is Iran's BGP routing table as seen from outside Iran — specifically, whether prefixes originating from Iranian ASNs have reachable next-hops in the global Internet routing table. The three approaches below attack this problem from different angles, and `run_all.R` merges their results into a confidence-scored output.

---

## Data Source Note: BGPView Shutdown

The original implementation used BGPView (`api.bgpview.io`) as the primary data source. **BGPView permanently shut down on November 26, 2025.** All data now comes from two sources:

- **RIPE NCC STAT** (`stat.ripe.net`) — free, authoritative, no API key needed for most endpoints
- **Team Cymru WHOIS** (`whois.cymru.com:43`) — raw TCP, free, no key needed

The RIPE STAT country-level endpoint (`country-asns`) was also found to silently return empty results even with the `data_overload_limit=ignore` bypass parameter, making it unreliable as a starting point. Approach 2 has been redesigned to not depend on any single country-level lookup.

---

## Approach 1 — RIPE Atlas Pings

### What it does

RIPE Atlas is a global network of more than 10,000 active hardware and software probes. The free API lets you create one-off measurements — ICMP ping sweeps — that run from any subset of those probes.

This approach uses RIPE STAT's `announced-prefixes` endpoint to fetch prefixes per ASN, selects one representative IP per prefix (the first usable host in the CIDR), and creates a RIPE Atlas ping measurement toward that IP from ~50 worldwide probes with Iranian probes explicitly excluded. It polls results after ~2 minutes and marks a prefix as routable if at least 25% of probes received at least one ICMP reply.

### Why it is the most accurate

BGP advertisements can lie. A router may propagate a prefix without the destination actually being reachable end-to-end (blackhole routes, null routes, last-mile filtering). Atlas pings verify actual ICMP reachability from diverse real-world vantage points. The 25% threshold tolerates ICMP filtering while still requiring a meaningful fraction of external probes to succeed.

### Requirements and limitations

- Requires a free RIPE Atlas account to create measurements (read-only queries need no key)
- Free accounts receive ~100 credits per day; each measurement costs ~5 credits — roughly 20 ASNs per day
- Measurement round-trip adds ~2–3 minutes of wait per batch
- ICMP can be filtered at the destination; no response is not always proof of non-reachability
- Seed ASNs must come from Approach 2 or be provided manually (no longer fetched from a country endpoint)

### Running it

```r
Sys.setenv(RIPE_ATLAS_API_KEY = "your-key-here")
source("approach1_ripe_atlas.R")
results <- find_routable_asns_atlas(max_asns = 20)
```

```bash
Rscript approach1_ripe_atlas.R --max-asns 20 --output atlas_results.json
```

### Key parameters

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `max_asns` | 20 | Number of ASNs to probe |
| `probe_count` | 50 | External Atlas probes per measurement |
| `min_ratio` | 0.25 | Fraction of successful probes required |
| `wait_secs` | 120 | Seconds to wait before polling results |

---

## Approach 2 — BGP Scan: Seed and Expand

### What it does

Rather than relying on a country-level API endpoint (which proved unreliable), this approach builds the Iranian ASN list from the ground up using four phases.

**Phase 1 — Hardcoded seed ASNs.** A curated set of 20 known-good Iranian ASNs drawn from manual research, BGP looking-glass queries, and Cymru WHOIS lookups against confirmed Iranian IPs. These are always available without any network call and cover the major Iranian carriers, ISPs, and CDNs.

| ASN | Organisation |
|-----|-------------|
| 43754 | Asiatech Data Transmission |
| 62229 | Fars News Agency |
| 48159 | TIC — Telecommunication Infrastructure Co (backbone) |
| 12880 | Information Technology Company (ITC) |
| 16322 | Pars Online |
| 44244 | Iran Cell (Irancell) |
| 58224 | Iran Telecommunication Company (TCI) |
| 197207 | Mobile Telecommunications Company of Iran |
| 205585 | ArvanCloud CDN |
| 49666 | Mobin Net |
| 57218 | RighTel Telecommunications |
| … | (20 total — see `SEED_ASNS` in `approach2_bgp_scan.R`) |

**Phase 2 — DNS resolution of Iranian domains → Cymru WHOIS.** A list of 20 known Iranian hostnames is resolved via DNS. Each resulting IP is sent to Team Cymru's bulk WHOIS service in a single TCP connection, which returns the ASN, BGP prefix, and country code for each IP instantly. Any ASN with `country=IR` is added to the working set. This phase can discover ASNs not in the seed list.

Note on split-horizon CDNs: some Iranian sites (Tasnimnews, Sepehr TV, Aparatchi) use ArvanCloud CDN, which intentionally serves European IPs to outside DNS resolvers. From Vancouver these will resolve to Frankfurt or Paris, not Iran. ArvanCloud itself (AS205585) is included as a seed because it is Iranian-origin and useful for neighbour expansion, but its resolved IPs are not useful as proxy targets.

**Phase 3 — ASN neighbour expansion (optional).** For each seed ASN, the RIPE STAT `asn-neighbours` endpoint returns BGP peers. Any neighbour ASN that appears in the peer sets of at least 2 different seeds is likely a legitimate Iranian transit or peer ASN and is added to the working set. This phase is skipped when `expand_neighbours = FALSE`.

**Phase 4 — Announced prefixes per ASN.** For every ASN in the working set, RIPE STAT's `announced-prefixes` endpoint returns all currently announced prefixes. Each prefix is filtered through the bogon list and length check before being added to the routable prefix list.

### Bogon filter

| Range | Reason |
|-------|--------|
| 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 | RFC 1918 private space |
| 100.64.0.0/10 | Shared address space (RFC 6598) |
| 169.254.0.0/16 | Link-local |
| 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 | Documentation test nets |
| 224.0.0.0/4, 240.0.0.0/4 | Multicast and reserved |
| Any IPv6 prefix | Not applicable for proxy use |
| Prefix length > /24 | Too specific; filtered globally |

### Running it

```r
# Recommended starting point — no keys needed, fast:
source("run_all.R")
results <- run_all(bgp_only = TRUE, expand_neighbours = FALSE)

# With neighbour expansion for broader coverage:
results <- run_all(bgp_only = TRUE)

# Add your own seed ASNs or domains:
results <- run_all(
  bgp_only      = TRUE,
  extra_asns    = c(12345L, 67890L),
  extra_domains = c("mysite.ir")
)

# Get a flat data frame:
df <- results_to_df(results)
write.csv(df, "iranian_routable_asns.csv", row.names = FALSE)
```

```bash
Rscript run_all.R --bgp-only --output bgp_only.json
Rscript run_all.R --bgp-only --no-expand --output bgp_no_expand.json
```

### Key parameters

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `expand_neighbours` | `TRUE` | Run Phase 3 neighbour expansion |
| `extra_asns` | `integer(0)` | Additional seed ASNs to include |
| `extra_domains` | `character(0)` | Additional domains for DNS phase |
| `min_shared_peers` | 2 | Min seed peers to accept a neighbour ASN |
| `delay` | 0.2 | Seconds between RIPE STAT requests |
| `max_asns` | `NULL` | Cap total ASNs processed |

### Known Iranian ASNs confirmed routable

The following were confirmed through manual BGP lookups and are included as seeds:

- **AS43754** (Asiatech) — confirmed via `telewebion.ir → 188.0.241.5`, globally routable
- **AS62229** (Fars News Agency) — `farsnews.ir` resolves to this ASN's own space, globally routable
- **AS48159** (TIC backbone) — `62.60.x.x` range, Iran's primary transit backbone
- **AS205585** (ArvanCloud) — Iranian CDN; uses split-horizon DNS so outside resolvers get European IPs; not useful as a proxy beacon but included for neighbour expansion

---

## Approach 3 — Reverse ASN Lookup from Proxy Candidates

### What it does

Rather than starting from the ASN list, this approach starts from a list of IP addresses — proxy candidates from any prior collection step — and works backwards to discover their ASNs.

For each candidate IP it queries ipinfo.io for the ASN, ASN name, and country code, falling back to Team Cymru WHOIS if ipinfo fails or returns no result. If `country = IR`, it TCP-probes common proxy ports (80, 443, 8080, 8443, 3128) with a configurable timeout. If the IP TCP-responds, its ASN is added to the confirmed-routable set with the responding port and round-trip time recorded. All lookups run in parallel using R's `future`/`future.apply` framework.

### The two lookup backends

**ipinfo.io** provides ASN, carrier name, and country code via HTTP JSON. Free accounts handle ~50,000 requests per month. The ASN is embedded in the `org` field as `"AS58224 Iran Telecommunication Company PJSC"`.

**Team Cymru WHOIS** is a raw TCP connection to `whois.cymru.com:43`. Sending `begin / verbose / {ip} / end` returns pipe-delimited rows with ASN, BGP prefix, country code, and ASN name. No authentication required. Used as the fallback when ipinfo is unavailable or rate-limited.

### Why it is useful

This approach is uniquely suited to cases where you already have a collection of candidate IPs. It simultaneously resolves ownership and verifies TCP reachability in one pass. It can also discover routable ASNs that the BGP scan missed — for example an ASN that only recently started announcing, or one whose prefix appears in a sub-allocation not directly indexed under the ASN.

### Running it

```r
source("approach3_reverse_asn.R")
ips     <- readLines("candidates.txt")
results <- find_routable_asns_reverse(ips, workers = 20)
print_reverse_summary(results)
```

```bash
Rscript approach3_reverse_asn.R \
  --input candidates.txt \
  --ipinfo-token $IPINFO_TOKEN \
  --workers 20 \
  --output reverse_asn_results.json
```

### Key parameters

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `workers` | 10 | Parallel futures for IP processing |
| `tcp_timeout` | 3.0 | Seconds per TCP connection attempt |
| `ipinfo_token` | `$IPINFO_TOKEN` | ipinfo.io token (empty = anonymous) |

---

## Running All Three Together

`run_all.R` sources all three scripts and merges results into a single list keyed by ASN, with a confidence score of 1–3 based on how many approaches confirmed each ASN.

```
Confidence 3/3 — VERY HIGH   confirmed by Atlas + BGP + reverse probe
Confidence 2/3 — HIGH        confirmed by any two approaches
Confidence 1/3 — POSSIBLE    confirmed by one approach only
```

```r
source("run_all.R")

# BGP only — no keys, recommended starting point:
results <- run_all(bgp_only = TRUE, expand_neighbours = FALSE)

# BGP with neighbour expansion:
results <- run_all(bgp_only = TRUE)

# Full run — all three approaches:
Sys.setenv(RIPE_ATLAS_API_KEY = "xxx")
Sys.setenv(IPINFO_TOKEN = "yyy")
results <- run_all(
  candidates         = "ips.txt",
  save_intermediates = TRUE,
  output             = "merged_routable_asns.json"
)

# Flat data frame + CSV export:
df <- results_to_df(results)
print(df)
write.csv(df, "iranian_routable_asns.csv", row.names = FALSE)

# Filter to high-confidence only:
high <- Filter(function(e) e$confidence >= 2, results)
```

```bash
# BGP only:
Rscript run_all.R --bgp-only --output bgp_only.json

# BGP without neighbour expansion:
Rscript run_all.R --bgp-only --no-expand --output bgp_no_expand.json

# Full run:
Rscript run_all.R \
  --candidates candidates.txt \
  --atlas-key $RIPE_ATLAS_API_KEY \
  --ipinfo-token $IPINFO_TOKEN \
  --output merged.json \
  --save-intermediates
```

---

## Approach Comparison

| | Approach 1 (Atlas) | Approach 2 (BGP Scan) | Approach 3 (Reverse) |
|---|---|---|---|
| **Starting point** | Seed ASN list | Hardcoded seeds + DNS | Candidate IP list |
| **What it verifies** | ICMP reachability from external probes | BGP announcement + prefix validity | TCP port reachability |
| **Ground truth** | Highest (actual ICMP end-to-end) | Medium–High (BGP + DNS confirmation) | High (TCP handshake) |
| **API key needed** | Yes (RIPE Atlas) | No | No (or optional ipinfo) |
| **Speed** | Slow (~2 min/batch) | Medium (scales with ASN count) | Fast (parallel) |
| **No-key quickstart** | No | Yes | No (needs candidate list) |
| **Finds new ASNs** | Yes | Yes (via neighbour expansion) | Only from known IPs |
| **Cost** | Free tier: ~20 ASNs/day | Free | Free |

---

## Bug History and Design Decisions

**BGPView shutdown (2025-11-26).** The original implementation used BGPView for both the country ASN list and per-prefix global visibility checks. Both endpoints became permanently unavailable. Replaced with RIPE STAT and a seed-based discovery strategy.

**RIPE STAT country-asns returning empty results.** After migrating to RIPE STAT, the `country-asns` endpoint returned 0 ASNs even with `data_overload_limit=ignore`. The endpoint was designed for browser widgets and throttles large result sets unpredictably. Replaced with the seed-and-expand strategy that does not depend on any country-level listing.

**IPv6 crash in prefix scan.** The `announced-prefixes` endpoint returns both IPv4 and IPv6 prefixes. The original bogon filter called `.cidr_range()` on IPv6 addresses, which failed with NAs, causing `if (is_bogon(...))` to throw "missing value where TRUE/FALSE needed". Fixed with an `is_ipv4_prefix()` guard that rejects anything not matching `x.x.x.x/n` before any numeric processing.

**DNS returning no IPs.** The original resolver used `nsl()` which is platform-inconsistent (returns `NULL` on some Linux builds). Replaced with `tools::nsl()` and a `system2("nslookup", ...)` fallback that works on Windows, macOS, and Linux.

**`filter(isTRUE(tcp_ok))` silently returning empty results.** `isTRUE()` is a scalar function; when passed a column vector inside `dplyr::filter()` it always returns `FALSE`. Changed to `filter(tcp_ok == TRUE)` throughout.

**`sys.frame(1)$ofile` error when sourcing interactively.** `sys.frame(1)` only has an `$ofile` attribute when a file is already being sourced at frame 1. In an interactive session it throws "not that many frames on the stack". Replaced with a three-tier resolver: `--file=` flag from `commandArgs()` → frame walk for `$ofile` → `getwd()` fallback.

---

## Required R Packages

```r
install.packages(c(
  "httr2",         # Modern HTTP client
  "jsonlite",      # JSON parsing and serialisation
  "dplyr",         # Data wrangling
  "cli",           # Formatted terminal output
  "future",        # Parallel execution backend (approach 3)
  "future.apply"   # Parallel lapply via future (approach 3)
))
```

All external HTTP communication uses `httr2`. Raw TCP connections (Team Cymru WHOIS, TCP probing) use base R's `socketConnection`. DNS resolution uses `tools::nsl()` with a `system2("nslookup")` fallback. No compiled extensions required.
