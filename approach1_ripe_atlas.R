# approach1_ripe_atlas.R
# ============================================================
# Approach 1: RIPE Atlas — Find Routable Iranian ASNs via
# External Probe Pings
# ============================================================
# Uses RIPE STAT API (stat.ripe.net) — BGPView shut down
# permanently on 2025-11-26.
#
# Steps:
#   1. Fetch all Iranian ASNs via RIPE STAT country-asns
#   2. Fetch announced prefixes per ASN via RIPE STAT
#   3. Create one-off Atlas ping measurements (external probes)
#   4. Poll results; mark routable if >=25% probes reply
#
# Requirements:
#   install.packages(c("httr2", "jsonlite", "dplyr", "cli"))
#
# Usage (interactive):
#   Sys.setenv(RIPE_ATLAS_API_KEY = "your-key-here")
#   source("approach1_ripe_atlas.R")
#   results <- find_routable_asns_atlas(max_asns = 20)
#
# Usage (Rscript):
#   Rscript approach1_ripe_atlas.R --max-asns 20 --output atlas_results.json
# ============================================================

suppressPackageStartupMessages({
  library(httr2)
  library(jsonlite)
  library(dplyr)
  library(cli)
})

`%||%` <- function(a, b) if (!is.null(a) && length(a) > 0 && !all(is.na(a))) a else b

STAT_BASE  <- "https://stat.ripe.net/data"
ATLAS_BASE <- "https://atlas.ripe.net/api/v2"

# ── HTTP helper ───────────────────────────────────────────────

safe_get <- function(url, query = list(), retries = 3L) {
  for (i in seq_len(retries)) {
    resp <- tryCatch(
      request(url) |>
        req_url_query(!!!query) |>
        req_headers(
          `User-Agent` = "iran-asn-atlas-r/2.0",
          `Accept`     = "application/json"
        ) |>
        req_timeout(30) |>
        req_perform(),
      error = function(e) NULL
    )
    if (!is.null(resp)) {
      status <- resp_status(resp)
      if (status == 200L)
        return(resp_body_json(resp, simplifyVector = TRUE))
      if (status == 429L) {
        wait <- as.integer(resp_header(resp, "Retry-After") %||% "10")
        cli_alert_warning("Rate-limited — sleeping {wait}s")
        Sys.sleep(wait); next
      }
    }
    Sys.sleep(2^(i - 1))
  }
  NULL
}

# ── Step 1: Iranian ASNs from RIPE STAT ──────────────────────
# Endpoint: /data/country-asns/data.json?resource=IR&lod=1
# lod=1 returns the actual ASN list (default lod=0 returns counts only)

get_iranian_asns <- function() {
  cli_progress_step("Fetching Iranian ASNs from RIPE STAT")
  data <- safe_get(
    paste0(STAT_BASE, "/country-asns/data.json"),
    query = list(resource = "IR", lod = 1)
  )
  if (is.null(data))
    stop("Could not fetch Iranian ASNs from RIPE STAT")
  
  d <- data$data
  # routed = currently visible in BGP; registered = allocated but may be dark
  routed     <- as.integer(d$routed     %||% integer(0))
  registered <- as.integer(d$registered %||% integer(0))
  # Combine and deduplicate; routed ones are higher-confidence
  all_asns <- unique(c(routed, registered))
  
  result <- data.frame(
    asn    = all_asns,
    routed = all_asns %in% routed,
    stringsAsFactors = FALSE
  )
  cli_alert_success(
    "{nrow(result)} ASNs ({length(routed)} routed, {length(registered)} registered)"
  )
  result
}

# ── Step 2: Announced prefixes per ASN from RIPE STAT ────────
# Endpoint: /data/announced-prefixes/data.json?resource=AS{n}

get_asn_prefixes <- function(asn) {
  data <- safe_get(
    paste0(STAT_BASE, "/announced-prefixes/data.json"),
    query = list(resource = paste0("AS", asn))
  )
  if (is.null(data)) return(character(0))
  pref <- data$data$prefixes
  if (is.null(pref)) return(character(0))
  if (is.data.frame(pref) && "prefix" %in% names(pref) && nrow(pref) > 0)
    return(pref$prefix)
  if (is.character(pref) && length(pref) > 0)
    return(pref)
  character(0)
}

# ── Step 3: First usable host in CIDR ────────────────────────

cidr_first_host <- function(cidr) {
  parts  <- strsplit(cidr, "/")[[1]]
  octets <- as.integer(strsplit(parts[1], "\\.")[[1]])
  octets[4] <- octets[4] + 1L
  paste(octets, collapse = ".")
}

# ── Step 4: Create Atlas ping measurement ────────────────────

create_ping_measurement <- function(target_ip,
                                    description = "Iran prefix reachability",
                                    probe_count = 50L,
                                    api_key     = Sys.getenv("RIPE_ATLAS_API_KEY")) {
  if (nchar(api_key) == 0) {
    cli_alert_warning("No RIPE_ATLAS_API_KEY — skipping ping for {target_ip}")
    return(NULL)
  }
  
  payload <- list(
    definitions = list(list(
      target           = target_ip,
      description      = description,
      type             = "ping",
      af               = 4L,
      packets          = 3L,
      size             = 48L,
      spread           = 60L,
      resolve_on_probe = FALSE
    )),
    probes = list(list(
      type      = "area",
      value     = "WW",
      requested = probe_count,
      tags      = list(exclude = list("country-IR"))
    )),
    is_oneoff = TRUE
  )
  
  resp <- tryCatch(
    request(paste0(ATLAS_BASE, "/measurements/")) |>
      req_method("POST") |>
      req_headers(
        Authorization  = paste("Key", api_key),
        `Content-Type` = "application/json"
      ) |>
      req_body_raw(toJSON(payload, auto_unbox = TRUE)) |>
      req_timeout(20) |>
      req_perform(),
    error = function(e) { cli_alert_danger("Request error: {e$message}"); NULL }
  )
  
  if (is.null(resp) || resp_status(resp) != 201L) {
    code <- if (!is.null(resp)) resp_status(resp) else "no response"
    cli_alert_danger("Failed for {target_ip} (HTTP {code})")
    return(NULL)
  }
  
  msm_id <- resp_body_json(resp)$measurements[[1]]
  cli_alert_success("Created measurement {msm_id} for {target_ip}")
  msm_id
}

# ── Step 5: Poll results ──────────────────────────────────────

poll_measurement <- function(msm_id, wait_seconds = 120L) {
  cli_progress_step("Waiting {wait_seconds}s for measurement {msm_id}")
  Sys.sleep(wait_seconds)
  data <- safe_get(paste0(ATLAS_BASE, "/measurements/", msm_id, "/results/"))
  if (is.null(data)) return(list())
  data
}

is_reachable <- function(probe_results, min_ratio = 0.25) {
  if (length(probe_results) == 0) return(FALSE)
  ok <- sum(sapply(probe_results, function(r)
    !is.null(r$avg) && !is.na(r$avg) && r$avg > 0))
  (ok / length(probe_results)) >= min_ratio
}

# ── Main ──────────────────────────────────────────────────────

find_routable_asns_atlas <- function(max_asns  = 20L,
                                     api_key   = Sys.getenv("RIPE_ATLAS_API_KEY"),
                                     wait_secs = 120L) {
  asn_df   <- get_iranian_asns()
  asn_df   <- head(asn_df, max_asns)
  results  <- list()
  pending  <- list()
  
  cli_h2("Launching measurements for {nrow(asn_df)} ASNs")
  
  for (i in seq_len(nrow(asn_df))) {
    asn      <- asn_df$asn[i]
    prefixes <- get_asn_prefixes(asn)
    
    if (length(prefixes) == 0) {
      cli_alert_info("AS{asn} — no announced prefixes, skipping")
      next
    }
    
    target_prefix <- prefixes[1]
    target_ip     <- cidr_first_host(target_prefix)
    cli_text("AS{asn} -> {target_prefix} -> probe {target_ip}")
    
    msm_id <- create_ping_measurement(
      target_ip   = target_ip,
      description = paste0("Iran AS", asn, " reachability"),
      api_key     = api_key
    )
    
    if (!is.null(msm_id)) {
      pending[[length(pending) + 1]] <- list(
        asn = asn, prefix = target_prefix, msm_id = msm_id
      )
    } else {
      results[[as.character(asn)]] <- list(
        asn      = asn,
        prefixes = prefixes,
        routable = NA,
        note     = "No Atlas key — reachability not checked"
      )
    }
    Sys.sleep(0.3)
  }
  
  if (length(pending) == 0) {
    cli_alert_warning("No measurements created — set RIPE_ATLAS_API_KEY.")
    return(results)
  }
  
  cli_h2("Collecting results for {length(pending)} measurements")
  for (p in pending) {
    raw       <- poll_measurement(p$msm_id, wait_seconds = wait_secs)
    reachable <- is_reachable(raw)
    n_ok      <- sum(sapply(raw, function(r) !is.null(r$avg) && r$avg > 0))
    label     <- if (reachable) cli::col_green("ROUTABLE") else cli::col_red("unreachable")
    cli_text("AS{p$asn}: {label} ({length(raw)} probes, {n_ok} successes)")
    
    results[[as.character(p$asn)]] <- list(
      asn                = p$asn,
      reachable_prefixes = if (reachable) p$prefix else character(0),
      routable           = reachable,
      measurement_id     = p$msm_id,
      probe_count        = length(raw),
      success_count      = n_ok
    )
  }
  
  n_ok <- sum(sapply(results, function(r) isTRUE(r$routable)))
  cli_alert_success("{n_ok} / {length(results)} ASNs confirmed routable via Atlas.")
  results
}

# ── CLI ───────────────────────────────────────────────────────

if (!interactive()) {
  .a   <- commandArgs(trailingOnly = TRUE)
  .max <- if ("--max-asns" %in% .a) as.integer(.a[which(.a == "--max-asns") + 1]) else 20L
  .out <- if ("--output"   %in% .a) .a[which(.a == "--output") + 1] else "atlas_results.json"
  .res <- find_routable_asns_atlas(max_asns = .max)
  write(toJSON(.res, auto_unbox = TRUE, pretty = TRUE), .out)
  cli_alert_success("Results written to {.out}")
}