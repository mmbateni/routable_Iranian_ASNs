# run_all.R
# ============================================================
# Iran Routable ASN Finder — Unified R Orchestrator
# ============================================================
# Sources all three approach scripts and merges their results
# into a single confidence-scored list.
#
# NOTE: BGPView shut down permanently on 2025-11-26.
#       All data now comes from RIPE NCC STAT (stat.ripe.net).
#
# Confidence scoring:
#   Each approach that confirms an ASN adds 1 point (max 3).
#   3 = very high | 2 = high | 1 = possible
#
# ── Interactive usage ─────────────────────────────────────────
#   source("run_all.R")
#
#   # BGP scan — seed+expand strategy, no keys needed:
#   results <- run_all(bgp_only = TRUE)
#
#   # Quick test (skip neighbour expansion, cap at 30 ASNs):
#   results <- run_all(bgp_only = TRUE, max_asns = 30, expand_neighbours = FALSE)
#
#   # Add your own seeds:
#   results <- run_all(
#     bgp_only      = TRUE,
#     extra_asns    = c(12345L, 67890L),
#     extra_domains = c("mysite.ir")
#   )
#
#   # Reverse lookup from a candidate IP list:
#   results <- run_all(reverse_only = TRUE, candidates = "ips.txt")
#
#   # Everything:
#   Sys.setenv(RIPE_ATLAS_API_KEY = "xxx", IPINFO_TOKEN = "yyy")
#   results <- run_all(candidates = "ips.txt")
#
# ── Get a flat data frame of results ─────────────────────────
#   df <- results_to_df(results)
#   write.csv(df, "iranian_routable_asns.csv", row.names = FALSE)
#
# ── Rscript usage ─────────────────────────────────────────────
#   Rscript run_all.R --bgp-only --output bgp.json
#   Rscript run_all.R --bgp-only --no-expand --max-asns 30
#   Rscript run_all.R --candidates ips.txt --output merged.json
#
# Requirements:
#   install.packages(c("httr2","jsonlite","dplyr","cli","future","future.apply"))
# ============================================================

suppressPackageStartupMessages({
  library(dplyr)
  library(jsonlite)
  library(cli)
})

`%||%` <- function(a, b) if (!is.null(a) && length(a) > 0 && !all(is.na(a))) a else b

# ── Resolve script directory ──────────────────────────────────
# Works in three contexts:
#   1. Rscript run_all.R       → --file= flag in commandArgs
#   2. source("run_all.R")     → $ofile set on the active frame
#   3. Fallback                → current working directory
.script_dir <- local({
  cmd  <- commandArgs(trailingOnly = FALSE)
  flag <- grep("^--file=", cmd, value = TRUE)
  if (length(flag)) {
    dirname(normalizePath(sub("^--file=", "", flag[1]), mustWork = FALSE))
  } else {
    ofile <- NULL
    for (i in seq_len(sys.nframe())) {
      f <- sys.frame(i)$ofile
      if (!is.null(f) && nchar(f) > 0) { ofile <- f; break }
    }
    if (!is.null(ofile)) dirname(normalizePath(ofile, mustWork = FALSE))
    else getwd()
  }
})

source(file.path(.script_dir, "approach1_ripe_atlas.R"),  local = TRUE)
source(file.path(.script_dir, "approach2_bgp_scan.R"),    local = TRUE)
source(file.path(.script_dir, "approach3_reverse_asn.R"), local = TRUE)

# ── Merge results from all approaches ────────────────────────

merge_results <- function(atlas   = NULL,
                          bgp     = NULL,
                          reverse = NULL) {
  entries <- list()
  
  add <- function(nm, asn, name, source, prefixes, resp_ips = list()) {
    prev <- entries[[nm]] %||% list(
      asn = asn, name = NULL, confidence = 0L,
      sources = character(0), prefixes = character(0),
      responsive_ips = list()
    )
    entries[[nm]] <<- modifyList(prev, list(
      name           = prev$name %||% name,
      confidence     = prev$confidence + 1L,
      sources        = c(prev$sources, source),
      prefixes       = unique(c(prev$prefixes, prefixes)),
      responsive_ips = c(prev$responsive_ips, resp_ips)
    ))
  }
  
  if (!is.null(atlas)) {
    for (nm in names(atlas)) {
      v <- atlas[[nm]]
      if (!isTRUE(v$routable)) next
      add(nm, as.integer(nm), NULL, "atlas", v$reachable_prefixes %||% character(0))
    }
  }
  
  if (!is.null(bgp)) {
    for (r in bgp) {
      if (!isTRUE(r$routable)) next
      nm <- as.character(r$asn)
      add(nm, r$asn, NULL, "bgp", r$routable_prefixes %||% character(0))
    }
  }
  
  if (!is.null(reverse)) {
    ra <- reverse$routable_asns
    if (!is.null(ra) && nrow(ra) > 0) {
      for (i in seq_len(nrow(ra))) {
        nm <- as.character(ra$asn[i])
        add(nm, ra$asn[i], ra$name[i], "reverse",
            ra$prefixes[[i]] %||% character(0),
            list(ra$responsive_ips[[i]]))
      }
    }
  }
  
  conf_labels <- c(`3` = "very_high", `2` = "high", `1` = "possible")
  for (nm in names(entries)) {
    conf <- entries[[nm]]$confidence
    entries[[nm]]$confidence_label <-
      conf_labels[as.character(conf)] %||% "possible"
  }
  
  entries
}

# ── Convert merged list to a flat data frame ─────────────────

results_to_df <- function(merged) {
  if (length(merged) == 0) return(data.frame())
  do.call(rbind, lapply(names(merged), function(nm) {
    e <- merged[[nm]]
    data.frame(
      asn              = e$asn,
      confidence       = e$confidence,
      confidence_label = e$confidence_label,
      sources          = paste(e$sources, collapse = "+"),
      n_prefixes       = length(e$prefixes),
      prefixes         = paste(e$prefixes, collapse = ", "),
      n_responsive_ips = length(e$responsive_ips),
      stringsAsFactors = FALSE
    )
  })) |> arrange(asn)
}

# ── Summary printer ───────────────────────────────────────────

print_merged_summary <- function(merged) {
  if (length(merged) == 0) {
    cli_alert_warning("No routable ASNs found across all approaches.")
    return(invisible(NULL))
  }
  all_conf <- sort(unique(sapply(merged, `[[`, "confidence")), decreasing = TRUE)
  for (conf in all_conf) {
    label   <- c(`3` = "VERY HIGH", `2` = "HIGH", `1` = "POSSIBLE")[as.character(conf)]
    entries <- Filter(function(e) e$confidence == conf, merged)
    cli_h2("Confidence {conf}/3 — {label} ({length(entries)} ASNs)")
    for (e in entries[order(sapply(entries, `[[`, "asn"))]) {
      pfxs    <- head(e$prefixes, 2)
      more    <- if (length(e$prefixes) > 2) paste0(" ...+", length(e$prefixes) - 2) else ""
      ip_tag  <- if (length(e$responsive_ips) > 0)
        paste0(" [", length(e$responsive_ips), " responsive IP(s)]") else ""
      cli_text(
        "  AS{formatC(e$asn,width=8)} ",
        "[{paste(e$sources,collapse='+')}]{ip_tag}"
      )
      if (length(pfxs) > 0)
        cli_text("           {paste(pfxs,collapse=', ')}{more}")
    }
  }
  cli_alert_success("Total: {length(merged)} unique routable Iranian ASNs identified.")
}

# ── Main entry point ──────────────────────────────────────────

run_all <- function(candidates         = NULL,
                    atlas_key          = Sys.getenv("RIPE_ATLAS_API_KEY"),
                    ipinfo_token       = Sys.getenv("IPINFO_TOKEN"),
                    max_asns           = NULL,
                    atlas_max_asns     = 20L,
                    bgp_delay          = 0.2,
                    expand_neighbours  = TRUE,
                    extra_asns         = integer(0),
                    extra_domains      = character(0),
                    tcp_timeout        = 3.0,
                    workers            = 10L,
                    bgp_only           = FALSE,
                    atlas_only         = FALSE,
                    reverse_only       = FALSE,
                    output             = "merged_routable_asns.json",
                    save_intermediates = FALSE) {
  
  atlas_res <- bgp_res <- reverse_res <- NULL
  
  if (!bgp_only && !reverse_only) {
    cli_rule("APPROACH 1: RIPE Atlas Pings")
    atlas_res <- find_routable_asns_atlas(
      max_asns = atlas_max_asns, api_key = atlas_key
    )
    if (save_intermediates)
      write(toJSON(atlas_res, auto_unbox = TRUE, pretty = TRUE), "atlas_raw.json")
  }
  
  if (!atlas_only && !reverse_only) {
    cli_rule("APPROACH 2: BGP Table Scan (Seed + Expand)")
    bgp_res <- scan_bgp_table(
      extra_asns        = extra_asns,
      extra_domains     = extra_domains,
      max_asns          = max_asns,
      delay             = bgp_delay,
      expand_neighbours = expand_neighbours
    )
    if (save_intermediates)
      write(toJSON(bgp_res, auto_unbox = TRUE, pretty = TRUE), "bgp_raw.json")
  }
  
  if (!atlas_only && !bgp_only) {
    if (!is.null(candidates)) {
      cli_rule("APPROACH 3: Reverse ASN Lookup")
      ips         <- readLines(candidates)
      reverse_raw <- find_routable_asns_reverse(
        ips          = ips,
        ipinfo_token = ipinfo_token,
        tcp_timeout  = tcp_timeout,
        workers      = workers
      )
      reverse_res <- reverse_raw
      if (save_intermediates)
        write(toJSON(reverse_raw$all_records, auto_unbox = TRUE, pretty = TRUE),
              "reverse_raw.json")
    } else {
      cli_alert_info(
        "Approach 3 skipped — pass candidates = \"ips.txt\" to enable."
      )
    }
  }
  
  cli_rule("MERGING RESULTS")
  merged <- merge_results(atlas_res, bgp_res, reverse_res)
  print_merged_summary(merged)
  
  write(toJSON(merged, auto_unbox = TRUE, pretty = TRUE), output)
  cli_alert_success("Written to {output}")
  
  invisible(merged)
}

# ── CLI ───────────────────────────────────────────────────────

if (!interactive()) {
  .a    <- commandArgs(trailingOnly = TRUE)
  .flag <- function(f) f %in% .a
  .opt  <- function(f, default = NULL) {
    i <- which(.a == f)
    if (length(i) > 0) .a[i + 1L] else default
  }
  
  run_all(
    candidates         = .opt("--candidates"),
    atlas_key          = .opt("--atlas-key",      Sys.getenv("RIPE_ATLAS_API_KEY")),
    ipinfo_token       = .opt("--ipinfo-token",   Sys.getenv("IPINFO_TOKEN")),
    max_asns           = if (!is.null(.opt("--max-asns")))
      as.integer(.opt("--max-asns")) else NULL,
    atlas_max_asns     = as.integer(.opt("--atlas-max-asns", "20")),
    bgp_delay          = as.numeric(.opt("--bgp-delay",      "0.2")),
    expand_neighbours  = !.flag("--no-expand"),
    tcp_timeout        = as.numeric(.opt("--tcp-timeout",    "3.0")),
    workers            = as.integer(.opt("--workers",        "10")),
    bgp_only           = .flag("--bgp-only"),
    atlas_only         = .flag("--atlas-only"),
    reverse_only       = .flag("--reverse-only"),
    output             = .opt("--output", "merged_routable_asns.json"),
    save_intermediates = .flag("--save-intermediates")
  )
}