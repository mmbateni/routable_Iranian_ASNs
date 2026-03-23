# approach3_reverse_asn.R
# ============================================================
# Approach 3: Reverse-Lookup ASN from Proxy Candidate IPs
# ============================================================
# Reads a list of candidate IPs, looks up each via ipinfo.io
# (falls back to Team Cymru WHOIS), then TCP-probes common
# proxy ports. Any IP that is country=IR AND TCP-responds
# contributes its ASN to the confirmed-routable set.
#
# Note: This approach never used BGPView, so no changes to
# the data sources — only minor code quality fixes carried
# over from the previous rewrite.
#
# Requirements:
#   install.packages(c("httr2", "jsonlite", "dplyr", "cli",
#                      "future", "future.apply"))
#
# Usage (interactive):
#   source("approach3_reverse_asn.R")
#   ips     <- readLines("candidates.txt")
#   results <- find_routable_asns_reverse(ips)
#
# Usage (Rscript):
#   Rscript approach3_reverse_asn.R --input candidates.txt --output reverse_asn_results.json
# ============================================================

suppressPackageStartupMessages({
  library(httr2)
  library(jsonlite)
  library(dplyr)
  library(cli)
  library(future)
  library(future.apply)
})

`%||%` <- function(a, b) if (!is.null(a) && length(a) > 0 && !all(is.na(a))) a else b

PROBE_PORTS <- c(80L, 443L, 8080L, 8443L, 3128L)

# ── Backend A: ipinfo.io ──────────────────────────────────────

lookup_ipinfo <- function(ip, token = Sys.getenv("IPINFO_TOKEN")) {
  req <- request(paste0("https://ipinfo.io/", ip, "/json")) |>
    req_headers(`User-Agent` = "iran-asn-reverse-r/2.0") |>
    req_timeout(10L)
  if (nchar(token) > 0)
    req <- req_url_query(req, token = token)
  
  resp <- tryCatch(req_perform(req), error = function(e) NULL)
  if (is.null(resp) || resp_status(resp) != 200L) return(NULL)
  
  d   <- resp_body_json(resp, simplifyVector = TRUE)
  org <- if (!is.null(d$org)) d$org else ""
  
  asn <- NA_integer_; asn_name <- NA_character_
  if (grepl("^AS", org)) {
    parts    <- strsplit(trimws(org), " ", fixed = TRUE)[[1]]
    asn      <- tryCatch(
      as.integer(sub("AS", "", parts[1], fixed = TRUE)),
      warning = function(e) NA_integer_
    )
    asn_name <- if (length(parts) > 1) paste(parts[-1], collapse = " ") else NA_character_
  }
  
  list(
    asn      = asn,
    asn_name = asn_name,
    prefix   = NA_character_,
    country  = if (!is.null(d$country)) d$country else NA_character_,
    source   = "ipinfo"
  )
}

# ── Backend B: Team Cymru WHOIS (whois.cymru.com:43) ─────────
# Columns: AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name

lookup_cymru <- function(ip) {
  result <- list(asn = NA_integer_, asn_name = NA_character_,
                 prefix = NA_character_, country = NA_character_,
                 source = "cymru")
  tryCatch({
    con <- socketConnection("whois.cymru.com", port = 43L,
                            open = "r+", blocking = TRUE, timeout = 10L)
    on.exit(try(close(con), silent = TRUE), add = TRUE)
    writeLines(c("begin", " verbose", ip, "end"), con)
    Sys.sleep(0.5)
    raw <- readLines(con, warn = FALSE)
    for (line in raw) {
      if (!grepl("|", line, fixed = TRUE)) next
      if (grepl("^Bulk|^AS ", line))       next
      parts <- trimws(strsplit(line, "|", fixed = TRUE)[[1]])
      if (length(parts) < 4) next
      result$asn      <- tryCatch(as.integer(parts[1]), warning = function(e) NA_integer_)
      result$prefix   <- if (nchar(parts[3]) > 0) parts[3] else NA_character_
      result$country  <- if (nchar(parts[4]) > 0) parts[4] else NA_character_
      result$asn_name <- if (length(parts) >= 7 && nchar(parts[7]) > 0)
        parts[7] else NA_character_
      break
    }
  }, error = function(e) NULL)
  result
}

# ── Combined lookup with fallback ────────────────────────────

lookup_asn <- function(ip, ipinfo_token = Sys.getenv("IPINFO_TOKEN")) {
  res <- tryCatch(lookup_ipinfo(ip, token = ipinfo_token), error = function(e) NULL)
  if (!is.null(res) && !is.na(res$asn)) return(res)
  tryCatch(lookup_cymru(ip), error = function(e)
    list(asn = NA_integer_, asn_name = NA_character_,
         prefix = NA_character_, country = NA_character_, source = "none"))
}

# ── TCP reachability probe ────────────────────────────────────

tcp_probe <- function(ip, ports = PROBE_PORTS, timeout = 3.0) {
  for (port in ports) {
    t0 <- proc.time()[["elapsed"]]
    ok <- tryCatch({
      con <- socketConnection(ip, port = port, open = "r+",
                              blocking = TRUE, timeout = timeout)
      try(close(con), silent = TRUE)
      TRUE
    }, error = function(e) FALSE)
    if (ok) {
      rtt <- round((proc.time()[["elapsed"]] - t0) * 1000, 1)
      return(list(ok = TRUE, port = port, rtt_ms = rtt))
    }
  }
  list(ok = FALSE, port = NA_integer_, rtt_ms = NA_real_)
}

# ── Process one IP ────────────────────────────────────────────

process_ip <- function(ip, ipinfo_token = "", tcp_timeout = 3.0) {
  info <- lookup_asn(ip, ipinfo_token = ipinfo_token)
  do_probe <- identical(info$country, "IR") || is.na(info$country)
  tcp <- if (do_probe) tcp_probe(ip, timeout = tcp_timeout)
  else list(ok = NA, port = NA_integer_, rtt_ms = NA_real_)
  list(
    ip            = ip,
    asn           = info$asn,
    asn_name      = info$asn_name,
    prefix        = info$prefix,
    country       = info$country,
    tcp_ok        = tcp$ok,
    tcp_port      = tcp$port,
    tcp_rtt_ms    = tcp$rtt_ms,
    lookup_source = info$source
  )
}

# ── Main batch processor ──────────────────────────────────────

find_routable_asns_reverse <- function(ips,
                                       ipinfo_token = Sys.getenv("IPINFO_TOKEN"),
                                       tcp_timeout  = 3.0,
                                       workers      = 10L) {
  ips <- unique(trimws(ips[nchar(trimws(ips)) > 0]))
  cli_alert_info("Processing {length(ips)} unique IPs with {workers} workers")
  
  plan(multisession, workers = workers)
  on.exit(plan(sequential), add = TRUE)
  
  all_records <- future_lapply(
    ips, FUN = process_ip,
    ipinfo_token = ipinfo_token,
    tcp_timeout  = tcp_timeout,
    future.seed  = TRUE
  )
  
  tbl <- do.call(rbind, lapply(all_records, function(r) {
    data.frame(
      ip            = r$ip,
      asn           = r$asn        %||% NA_integer_,
      asn_name      = r$asn_name   %||% NA_character_,
      prefix        = r$prefix     %||% NA_character_,
      country       = r$country    %||% NA_character_,
      tcp_ok        = r$tcp_ok     %||% NA,
      tcp_port      = r$tcp_port   %||% NA_integer_,
      tcp_rtt_ms    = r$tcp_rtt_ms %||% NA_real_,
      lookup_source = r$lookup_source %||% NA_character_,
      stringsAsFactors = FALSE
    )
  }))
  
  cat("\n")
  cli_h2("Per-IP Results")
  for (i in seq_len(nrow(tbl))) {
    r      <- tbl[i, ]
    cc     <- if (!is.na(r$country)) r$country else "??"
    asntag <- if (!is.na(r$asn)) paste0("AS", r$asn) else "ASN?"
    rtag   <- if (isTRUE(r$tcp_ok)) paste0(r$tcp_rtt_ms, "ms")
    else if (identical(r$tcp_ok, FALSE)) "timeout" else ""
    sym    <- if (isTRUE(r$tcp_ok))  cli::col_green("v")
    else if (cc == "IR")    cli::col_red("x")
    else                    "."
    cli_text(
      "{sym} {formatC(r$ip,width=18,flag='-')} ",
      "{formatC(cc,width=4,flag='-')} ",
      "{formatC(asntag,width=12,flag='-')} {rtag}"
    )
  }
  
  # Aggregate routable Iranian ASNs
  # Use tcp_ok == TRUE (not isTRUE) so dplyr filter works on the column vector
  iranian_ok <- tbl |>
    filter(country == "IR", tcp_ok == TRUE, !is.na(asn))
  
  routable_asns <- iranian_ok |>
    group_by(asn) |>
    summarise(
      name           = dplyr::first(asn_name),
      prefixes       = list(unique(na.omit(prefix))),
      responsive_ips = list(
        data.frame(ip = ip, port = tcp_port, rtt_ms = tcp_rtt_ms)
      ),
      .groups = "drop"
    )
  
  cli_alert_success(
    "Found {nrow(routable_asns)} routable Iranian ASNs from {length(ips)} candidates."
  )
  list(routable_asns = routable_asns, all_records = tbl)
}

# ── Summary ───────────────────────────────────────────────────

print_reverse_summary <- function(results) {
  r <- results$routable_asns
  if (is.null(r) || nrow(r) == 0) {
    cli_alert_warning("No routable Iranian ASNs found.")
    return(invisible(NULL))
  }
  cli_h1("Routable Iranian ASNs ({nrow(r)})")
  for (i in seq_len(nrow(r))) {
    name_str <- if (!is.na(r$name[i])) r$name[i] else ""
    cli_text(
      "  AS{formatC(r$asn[i],width=8)} ",
      "{formatC(name_str,width=40,flag='-')} ",
      "{nrow(r$responsive_ips[[i]])} responsive IP(s)"
    )
  }
}

# ── CLI ───────────────────────────────────────────────────────

if (!interactive()) {
  .a    <- commandArgs(trailingOnly = TRUE)
  .in   <- if ("--input"        %in% .a) .a[which(.a == "--input")        + 1] else stop("--input required")
  .tok  <- if ("--ipinfo-token" %in% .a) .a[which(.a == "--ipinfo-token") + 1] else Sys.getenv("IPINFO_TOKEN")
  .tout <- if ("--tcp-timeout"  %in% .a) as.numeric(.a[which(.a == "--tcp-timeout") + 1]) else 3.0
  .wkrs <- if ("--workers"      %in% .a) as.integer(.a[which(.a == "--workers")     + 1]) else 10L
  .out  <- if ("--output"       %in% .a) .a[which(.a == "--output") + 1] else "reverse_asn_results.json"
  
  .ips <- readLines(.in)
  .res <- find_routable_asns_reverse(.ips, ipinfo_token = .tok,
                                     tcp_timeout = .tout, workers = .wkrs)
  print_reverse_summary(.res)
  
  out_list <- list(
    routable_asns = .res$routable_asns |>
      mutate(prefixes  = sapply(prefixes, function(x) paste(x, collapse = ",")),
             ip_count  = sapply(responsive_ips, nrow)) |>
      select(-responsive_ips),
    all_records = .res$all_records
  )
  write(toJSON(out_list, auto_unbox = TRUE, pretty = TRUE), .out)
  cli_alert_success("Results written to {.out}")
}