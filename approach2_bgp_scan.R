# approach2_bgp_scan.R
# ============================================================
# Approach 2: Find Routable Iranian ASNs — Seed & Expand
# ============================================================
# The RIPE STAT country-level endpoint (country-asns,
# country-resource-list) is unreliable and often returns
# empty results. This script uses a more robust strategy:
#
# STEP 1 — Seed ASNs
#   Hardcoded set of known-good Iranian ASNs drawn from
#   manual research (telewebion, farsnews, TIC backbone,
#   ArvanCloud, etc.) plus any user-supplied extras.
#
# STEP 2 — DNS-resolve Iranian sites → IPs → Cymru WHOIS
#   Resolve a curated list of known Iranian hostnames.
#   For each resolved IP, Team Cymru WHOIS returns its ASN
#   and BGP prefix instantly. Any ASN with country=IR is
#   added to the working set.
#
# STEP 3 — Expand via ASN neighbours (RIPE STAT)
#   For each seed ASN, query RIPE STAT asn-neighbours to
#   find BGP peers. Neighbours that appear in multiple
#   seed peer-sets are likely Iranian transit/peer ASNs.
#
# STEP 4 — Fetch announced prefixes (RIPE STAT)
#   For every ASN in the working set, call announced-prefixes
#   and bogon-filter the results.
#
# Requirements:
#   install.packages(c("httr2", "jsonlite", "dplyr", "cli"))
#
# Usage (interactive):
#   source("approach2_bgp_scan.R")
#   results <- scan_bgp_table()
#   print_bgp_summary(results)
#
#   # Add your own seed ASNs or domains:
#   results <- scan_bgp_table(
#     extra_asns    = c(12345L, 67890L),
#     extra_domains = c("mysite.ir", "example.ir")
#   )
#
# Usage (Rscript):
#   Rscript approach2_bgp_scan.R --output bgp_scan_results.json
# ============================================================

suppressPackageStartupMessages({
  library(httr2)
  library(jsonlite)
  library(dplyr)
  library(cli)
})

`%||%` <- function(a, b) if (!is.null(a) && length(a) > 0 && !all(is.na(a))) a else b

STAT_BASE <- "https://stat.ripe.net/data"

# ── Known-good Iranian seed ASNs ─────────────────────────────
# Sources: manual research, BGP looking-glass, Cymru WHOIS.
# ArvanCloud (205585) intentionally geo-splits DNS — useful as
# a neighbour probe but not as a proxy target itself.

SEED_ASNS <- c(
  43754L,   # Asiatech Data Transmission (telewebion.ir)
  62229L,   # Fars News Agency
  48159L,   # TIC — Telecommunication Infrastructure Co (backbone)
  12880L,   # Information Technology Company (ITC)
  16322L,   # Pars Online
  44244L,   # Iran Cell Service and Communication (Irancell)
  58224L,   # Iran Telecommunication Company (TCI/Hamrah-e-Avval)
  24631L,   # Fanava Group
  25184L,   # Afranet
  31549L,   # Aria Shatel
  197207L,  # Mobile Telecommunications Company of Iran
  205585L,  # ArvanCloud CDN (IR-origin, useful for neighbour expansion)
  56402L,   # Chapar Khane Pardazesh Dadeh (CPD)
  42337L,   # Respina Networks
  47262L,   # Iran Internet Exchange (IIX)
  49666L,   # Mobin Net
  51695L,   # Pishgaman Toseeh Ertebatat (PTE)
  57218L,   # RighTel Telecommunications
  59587L,   # Shatel Mobile
  39501L    # Shabakeh Gostar Mehr
)

# ── Known Iranian domains for DNS-seed discovery ─────────────

SEED_DOMAINS <- c(
  "telewebion.ir",
  "farsnews.ir",
  "tasnimnews.ir",
  "sepehrtv.ir",
  "parsatv.com",
  "aparatchi.com",
  "imvbox.com",
  "irna.ir",
  "isna.ir",
  "mehrnews.com",
  "iribnews.ir",
  "varzesh3.com",
  "namasha.com",
  "filimo.com",
  "aparat.com",
  "digikala.com",
  "snapp.ir",
  "irancell.ir",
  "mci.ir",
  "tic.ir"
)

# ── Bogon filter ──────────────────────────────────────────────

BOGON_RANGES <- c(
  "0.0.0.0/8",       "10.0.0.0/8",      "100.64.0.0/10",
  "127.0.0.0/8",     "169.254.0.0/16",  "172.16.0.0/12",
  "192.0.0.0/24",    "192.0.2.0/24",    "192.168.0.0/16",
  "198.18.0.0/15",   "198.51.100.0/24", "203.0.113.0/24",
  "224.0.0.0/4",     "240.0.0.0/4",     "255.255.255.255/32"
)

.cidr_range <- function(cidr) {
  p <- strsplit(cidr, "/")[[1]]
  o <- as.numeric(strsplit(p[1], "\\.")[[1]])
  m <- as.integer(p[2])
  n <- sum(o * c(2^24, 2^16, 2^8, 1))
  list(net = n, size = 2^(32 - m), mask = m)
}
.BOGONS <- lapply(BOGON_RANGES, .cidr_range)

is_ipv4_prefix <- function(prefix) {
  # Must match x.x.x.x/n — rejects IPv6 (colons) and bare IPs
  grepl("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}$", prefix)
}

is_bogon <- function(prefix) {
  if (!is_ipv4_prefix(prefix)) return(TRUE)   # drop IPv6 / malformed
  tryCatch({
    p <- .cidr_range(prefix)
    if (is.na(p$net) || is.na(p$size)) return(TRUE)
    p_e <- p$net + p$size - 1
    any(sapply(.BOGONS, function(b) !(p_e < b$net || (b$net + b$size - 1) < p$net)))
  }, error = function(e) TRUE)
}

prefix_length_sane <- function(prefix) {
  if (!is_ipv4_prefix(prefix)) return(FALSE)
  tryCatch(as.integer(strsplit(prefix, "/")[[1]][2]) <= 24L,
           error = function(e) FALSE)
}

# ── HTTP helper ───────────────────────────────────────────────

safe_get <- function(url, query = list(), retries = 3L) {
  for (i in seq_len(retries)) {
    resp <- tryCatch(
      request(url) |>
        req_url_query(!!!query) |>
        req_headers(`User-Agent` = "iran-asn-scan-r/2.1",
                    `Accept`     = "application/json") |>
        req_timeout(30) |>
        req_perform(),
      error = function(e) NULL
    )
    if (!is.null(resp)) {
      st <- resp_status(resp)
      if (st == 200L) return(resp_body_json(resp, simplifyVector = TRUE))
      if (st == 429L) {
        w <- as.integer(resp_header(resp, "Retry-After") %||% "10")
        cli_alert_warning("Rate-limited — sleeping {w}s"); Sys.sleep(w); next
      }
    }
    Sys.sleep(2^(i - 1))
  }
  NULL
}

# ── STEP 1+2: DNS resolve → Cymru WHOIS → ASN ────────────────

.resolve_domain <- function(domain) {
  # Try tools::nsl first (works on Linux/Mac)
  ips <- tryCatch({
    res <- tools::nsl(domain)
    if (is.null(res)) return(character(0))
    if (is.character(res)) return(res)
    if (is.list(res) && is.data.frame(res$answer))
      return(as.character(res$answer$data))
    character(0)
  }, error = function(e) character(0))
  
  if (length(ips) > 0) return(ips)
  
  # Fallback: system nslookup (works on Windows too)
  tryCatch({
    out  <- system2("nslookup", domain, stdout = TRUE, stderr = FALSE)
    # nslookup output lines: "Address: 1.2.3.4"
    addr <- grep("^Address:", out, value = TRUE)
    # Strip "Address: " prefix and exclude nameserver line (first Address line)
    ips  <- sub("^Address:\\s*", "", addr)
    ips  <- ips[grepl("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$", ips)]
    unique(ips)
  }, error = function(e) character(0))
}

.cymru_batch <- function(ips) {
  # Queries Team Cymru WHOIS for a batch of IPs in one TCP connection.
  # Returns data frame: ip, asn, prefix, country, asn_name
  if (length(ips) == 0) return(data.frame())
  
  result <- tryCatch({
    con <- socketConnection("whois.cymru.com", port = 43L,
                            open = "r+", blocking = TRUE, timeout = 15L)
    on.exit(try(close(con), silent = TRUE), add = TRUE)
    
    query <- c("begin", " verbose", ips, "end")
    writeLines(query, con)
    Sys.sleep(1)
    raw <- readLines(con, warn = FALSE)
    
    rows <- list()
    for (line in raw) {
      if (!grepl("|", line, fixed = TRUE)) next
      if (grepl("^Bulk|^AS ", line))       next
      p <- trimws(strsplit(line, "|", fixed = TRUE)[[1]])
      if (length(p) < 4) next
      rows[[length(rows) + 1]] <- data.frame(
        asn      = suppressWarnings(as.integer(p[1])),
        ip       = p[2],
        prefix   = p[3],
        country  = p[4],
        asn_name = if (length(p) >= 7) p[7] else NA_character_,
        stringsAsFactors = FALSE
      )
    }
    if (length(rows) == 0) return(data.frame())
    do.call(rbind, rows)
  }, error = function(e) {
    cli_alert_warning("Cymru WHOIS error: {e$message}")
    data.frame()
  })
  result
}

discover_asns_via_dns <- function(domains = SEED_DOMAINS) {
  cli_progress_step("Resolving {length(domains)} Iranian domains via DNS")
  
  all_ips <- character(0)
  for (d in domains) {
    ips <- .resolve_domain(d)
    if (length(ips) > 0) {
      cli_text("  {d} -> {paste(ips, collapse=', ')}")
      all_ips <- c(all_ips, ips)
    }
  }
  all_ips <- unique(all_ips)
  
  if (length(all_ips) == 0) {
    cli_alert_warning("DNS resolution returned no IPs — check connectivity")
    return(data.frame())
  }
  
  cli_progress_step("Querying Team Cymru WHOIS for {length(all_ips)} IPs")
  whois_df <- .cymru_batch(all_ips)
  
  if (nrow(whois_df) == 0) return(data.frame())
  
  # Keep only Iranian-origin ASNs
  ir_df <- whois_df[!is.na(whois_df$country) & whois_df$country == "IR", ]
  cli_alert_success(
    "DNS+Cymru: {nrow(ir_df)} Iranian IP records -> ",
    "{length(unique(na.omit(ir_df$asn)))} unique ASNs"
  )
  ir_df
}

# ── STEP 3: Expand via ASN neighbours ────────────────────────

get_asn_neighbours <- function(asn, delay = 0.25) {
  Sys.sleep(delay)
  raw <- safe_get(
    paste0(STAT_BASE, "/asn-neighbours/data.json"),
    query = list(resource = paste0("AS", asn))
  )
  if (is.null(raw)) return(integer(0))
  nb <- raw$data$neighbours
  if (is.null(nb) || length(nb) == 0) return(integer(0))
  if (is.data.frame(nb) && "asn" %in% names(nb))
    return(as.integer(nb$asn))
  as.integer(nb)
}

expand_via_neighbours <- function(seed_asns,
                                  min_shared_peers = 2L,
                                  delay            = 0.25) {
  cli_progress_step(
    "Expanding via ASN neighbours for {length(seed_asns)} seeds"
  )
  
  peer_count <- integer(0)  # named: how many seeds share each neighbour
  
  pb <- cli_progress_bar("Neighbour fetch", total = length(seed_asns),
                         clear = FALSE)
  for (asn in seed_asns) {
    nb <- get_asn_neighbours(asn, delay = delay)
    # Exclude the seeds themselves
    nb <- setdiff(nb, seed_asns)
    for (n in nb) {
      nm <- as.character(n)
      peer_count[nm] <- (peer_count[nm] %||% 0L) + 1L
    }
    cli_progress_update(id = pb)
  }
  cli_progress_done(id = pb)
  
  # Keep only neighbours peered with >=min_shared_peers seeds
  candidate_asns <- as.integer(names(peer_count[peer_count >= min_shared_peers]))
  cli_alert_success(
    "{length(candidate_asns)} candidate ASNs share ",
    ">={min_shared_peers} seed peers"
  )
  candidate_asns
}

# ── STEP 4: Fetch announced prefixes per ASN ─────────────────

get_asn_prefixes <- function(asn, delay = 0.2) {
  Sys.sleep(delay)
  raw <- safe_get(
    paste0(STAT_BASE, "/announced-prefixes/data.json"),
    query = list(resource = paste0("AS", asn))
  )
  if (is.null(raw)) return(character(0))
  pref <- raw$data$prefixes
  if (is.null(pref)) return(character(0))
  if (is.data.frame(pref) && "prefix" %in% names(pref) && nrow(pref) > 0)
    return(pref$prefix)
  if (is.character(pref) && length(pref) > 0)
    return(pref)
  character(0)
}

# ── RIPE STAT: AS overview (name lookup) ─────────────────────

get_asn_name <- function(asn) {
  raw <- safe_get(
    paste0(STAT_BASE, "/as-overview/data.json"),
    query = list(resource = paste0("AS", asn))
  )
  if (is.null(raw)) return(NA_character_)
  raw$data$holder %||% NA_character_
}

# ── Main orchestrator ─────────────────────────────────────────

scan_bgp_table <- function(extra_asns        = integer(0),
                           extra_domains     = character(0),
                           max_asns          = NULL,
                           min_shared_peers  = 2L,
                           delay             = 0.2,
                           expand_neighbours = TRUE,
                           fetch_names       = FALSE) {
  
  # ── 1+2: Seed + DNS discovery ──
  cli_h2("Phase 1+2: Seed ASNs + DNS/Cymru discovery")
  
  seed_asns <- unique(c(SEED_ASNS, as.integer(extra_asns)))
  cli_alert_info("{length(seed_asns)} hardcoded seed ASNs")
  
  all_domains <- unique(c(SEED_DOMAINS, extra_domains))
  dns_df      <- discover_asns_via_dns(all_domains)
  
  dns_asns <- if (nrow(dns_df) > 0) unique(na.omit(dns_df$asn)) else integer(0)
  
  # Merge seeds + DNS-discovered ASNs
  working_asns <- unique(c(seed_asns, dns_asns))
  cli_alert_success("{length(working_asns)} ASNs after seed + DNS merge")
  
  # ── 3: Neighbour expansion ──
  if (expand_neighbours) {
    cli_h2("Phase 3: ASN neighbour expansion")
    neighbour_asns <- expand_via_neighbours(
      seed_asns        = seed_asns,
      min_shared_peers = min_shared_peers,
      delay            = delay
    )
    working_asns <- unique(c(working_asns, neighbour_asns))
    cli_alert_success("{length(working_asns)} ASNs after neighbour expansion")
  }
  
  if (!is.null(max_asns)) {
    working_asns <- head(working_asns, max_asns)
    cli_alert_info("Capped at {max_asns} ASNs")
  }
  
  # ── 4: Fetch prefixes ──
  cli_h2("Phase 4: Fetching announced prefixes for {length(working_asns)} ASNs")
  pb      <- cli_progress_bar("Prefix fetch", total = length(working_asns),
                              clear = FALSE)
  results <- vector("list", length(working_asns))
  
  for (i in seq_along(working_asns)) {
    asn <- working_asns[i]
    
    name <- if (fetch_names) get_asn_name(asn) else NA_character_
    
    # Check if this ASN came from confirmed DNS/Cymru match
    dns_match  <- asn %in% dns_asns
    is_seed    <- asn %in% seed_asns
    prefixes   <- get_asn_prefixes(asn, delay = delay)
    
    routable_prefixes <- character(0)
    n_bogon <- n_long <- 0L
    for (pfx in prefixes) {
      if (is_bogon(pfx))            { n_bogon <- n_bogon + 1L; next }
      if (!prefix_length_sane(pfx)) { n_long  <- n_long  + 1L; next }
      routable_prefixes <- c(routable_prefixes, pfx)
    }
    
    # Routable if: is a known seed, or DNS-confirmed, or has valid prefixes
    is_routable <- is_seed || dns_match || length(routable_prefixes) > 0
    
    results[[i]] <- list(
      asn               = asn,
      name              = name,
      is_seed           = is_seed,
      dns_confirmed     = dns_match,
      all_prefixes      = prefixes,
      routable_prefixes = routable_prefixes,
      skipped_bogon     = n_bogon,
      skipped_too_long  = n_long,
      routable          = is_routable
    )
    
    sym    <- if (is_routable) cli::col_green("\u2713") else "\u00b7"
    origin <- if (is_seed) "[seed]" else if (dns_match) "[dns]" else "[nb]"
    cli_text(
      "{sym} AS{formatC(asn,width=8)} {formatC(origin,width=7)} ",
      "{length(routable_prefixes)}/{length(prefixes)} valid prefixes"
    )
    cli_progress_update(id = pb)
  }
  
  cli_progress_done(id = pb)
  
  n_routable <- sum(sapply(results, function(r) isTRUE(r$routable)))
  cli_alert_success("{n_routable} / {length(results)} ASNs confirmed routable.")
  results
}

# ── Summary ───────────────────────────────────────────────────

print_bgp_summary <- function(results) {
  if (length(results) == 0) {
    cli_alert_warning("No results to summarise.")
    return(invisible(NULL))
  }
  
  routable     <- Filter(function(r) isTRUE(r$routable), results)
  not_routable <- Filter(function(r) !isTRUE(r$routable), results)
  
  cli_h1("Routable ASNs ({length(routable)})")
  for (r in routable) {
    pfxs   <- head(r$routable_prefixes, 3)
    more   <- if (length(r$routable_prefixes) > 3)
      paste0(" ...+", length(r$routable_prefixes) - 3) else ""
    origin <- if (isTRUE(r$is_seed)) "[seed]" else
      if (isTRUE(r$dns_confirmed)) "[dns]" else "[nb]"
    name   <- if (!is.na(r$name) && !is.null(r$name)) paste0(" ", r$name) else ""
    cli_text(
      "  AS{formatC(r$asn,width=8)} {origin}{name}  ",
      "[{paste(pfxs,collapse=', ')}{more}]"
    )
  }
  
  if (length(not_routable) > 0) {
    cli_h1("ASNs with no routable prefixes ({length(not_routable)})")
    for (r in not_routable) {
      reason <- if (length(r$all_prefixes) == 0) "dark / not announcing"
      else "only bogon or too-specific prefixes"
      cli_text("  AS{formatC(r$asn,width=8)}  ({reason})")
    }
  }
}

# ── CLI ───────────────────────────────────────────────────────

if (!interactive()) {
  .a      <- commandArgs(trailingOnly = TRUE)
  .delay  <- if ("--delay"       %in% .a) as.numeric(.a[which(.a == "--delay")    + 1]) else 0.2
  .max    <- if ("--max-asns"    %in% .a) as.integer(.a[which(.a == "--max-asns") + 1]) else NULL
  .msp    <- if ("--min-peers"   %in% .a) as.integer(.a[which(.a == "--min-peers")+ 1]) else 2L
  .nonb   <- "--no-expand" %in% .a
  .names  <- "--fetch-names" %in% .a
  .out    <- if ("--output"      %in% .a) .a[which(.a == "--output") + 1] else "bgp_scan_results.json"
  
  .res <- scan_bgp_table(
    max_asns          = .max,
    min_shared_peers  = .msp,
    delay             = .delay,
    expand_neighbours = !.nonb,
    fetch_names       = .names
  )
  print_bgp_summary(.res)
  write(toJSON(.res, auto_unbox = TRUE, pretty = TRUE), .out)
  cli_alert_success("Results written to {.out}")
}