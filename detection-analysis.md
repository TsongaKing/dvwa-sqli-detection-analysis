# DVWA SQL Injection — Attack Traffic Detection Analysis

**Source capture:** `dvwa_sqli_attack.pcap` (415 KB, 614 packets)
**Attack tool:** sqlmap 1.10.8
**Target:** DVWA `vulnerabilities/sqli/` endpoint, security level: low
**Attacker IP:** 192.168.68.113 (Kali VM)
**Target IP:** 192.168.68.111:8080 (DVWA/Docker host)
**Capture window:** 2026-10-01, 11:51:20 – 11:51:34 (~14 seconds of active probing, plus a final extraction burst)

This document analyzes the captured attack traffic and identifies the specific signatures a detection system (SIEM rule, IDS, or the planned SOC investigation agent) should flag. It is written as a specification: a future implementation of the agent should be able to reproduce these findings automatically from the same pcap.

---

## 1. Volumetric / behavioral anomaly

- **~170 HTTP requests from a single source IP to a single endpoint** (`/vulnerabilities/sqli/`) within a ~14 second window.
- No human user issues 170 near-identical requests to one page in 14 seconds. This request rate and repetition alone is a strong anomaly signal, independent of payload content.
- **Detection rule:** flag any source IP issuing more than N requests (e.g. 20) to the same endpoint within a short rolling window (e.g. 30 seconds).

## 2. User-Agent signature

- Every single request in the capture carries the identical, unmodified User-Agent string:
  ```
  sqlmap/1.10.8#stable (https://sqlmap.org)
  ```
- This is the single most reliable and cheapest signal in the entire capture. The attacker made no attempt to obscure tool identity (sqlmap supports `--random-agent` / `--user-agent` to evade this, and did not use it here).
- **Detection rule:** maintain a blocklist/watchlist of known offensive-tool User-Agent substrings (`sqlmap`, `nikto`, `nmap`, `gobuster`, etc.) and flag/block on match. This is standard practice and would have caught this attack on request #1.

## 3. SQL keyword presence in URL parameters

The `id` parameter — normally expected to hold a small integer — instead carries SQL syntax across nearly every request. Representative patterns observed:

| Technique | Example fragment |
|---|---|
| Boolean-based | `id=1' OR NOT 3416=3416#` |
| Error-based | `EXTRACTVALUE(3408,CONCAT(0x5c,...))` |
| Time-based blind | `AND (SELECT 5159 FROM (SELECT(!SLEEP(5)))RGbE)--` |
| UNION-based | `UNION ALL SELECT CONCAT(...),NULL#` |
| Stacked query probe | `1';SELECT SLEEP(5)#` |
| Schema enumeration | `FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name=0x7573657273` |
| Direct data exfiltration | `FROM dvwa.users#` (final request — see §5) |

- **Detection rule:** flag any request where a URL parameter contains SQL keywords/operators (`UNION`, `SELECT`, `SLEEP`, `BENCHMARK`, `EXTRACTVALUE`, `OR 1=1`-style boolean patterns, `information_schema`, `--`, `#`, `'` in unexpected positions). This is the classic WAF signature category and would catch the majority of these requests individually.

## 4. Timing-based signature (time-based blind injection)

- A clear ~5 second gap is visible in the capture between `11:51:24.634868` and `11:51:29.636338`, corresponding exactly to a `SLEEP(5)` payload being executed server-side before the response returned.
- This is detectable **without reading the payload at all** — simply correlating request timestamp to response timestamp and flagging anomalously slow responses (especially in multiples of round numbers like 5s, which strongly suggest a deliberate `SLEEP()`/`BENCHMARK()` call rather than genuine server load).
- **Detection rule:** flag response latency outliers per-endpoint, especially when latency clusters around round-number values.

## 5. Data exfiltration marker (highest severity, lowest volume)

- The attack's final request is structurally different from everything before it — it is the only request that directly references the sensitive table by name:
  ```
  ...FROM dvwa.users#
  ```
  and explicitly selects the `password`, `user`, `role`, and other account columns via a `JSON_ARRAYAGG` aggregation.
- This single request represents the actual data breach moment — everything before it was reconnaissance/fingerprinting (confirming the injection worked, finding the column count, identifying the DBMS version). This one request is where real user data left the database.
- **Detection rule:** this is the highest-priority alert of the whole sequence. A query referencing an authentication/credentials table (`users`, `accounts`, `credentials`, `password`) via injection should trigger a critical severity alert distinct from the lower-severity "injection attempt detected" alerts in §3.

## 6. Suggested alert severity tiering

| Signal | Severity | Why |
|---|---|---|
| Known-malicious User-Agent | Medium | Cheap, reliable, but tool identity alone isn't proof of success |
| High request volume to one endpoint | Medium | Could be automated testing, not always malicious |
| SQL keywords in parameters | High | Strong indicator of active injection attempt |
| Anomalous response timing | High | Confirms time-based technique is actually working against the DB |
| Query referencing credentials table | Critical | Confirms actual data exposure, not just an attempt |

## 7. What this means for the agent build

A minimal working version of the SOC investigation agent should, at minimum, be able to:
1. Parse a pcap/HTTP log and extract request metadata (source IP, timestamp, URI, User-Agent).
2. Apply the five signatures above as independent detection rules.
3. Correlate them into a single incident timeline per source IP (reconnaissance → exploitation → exfiltration), since no individual request tells the full story — the *sequence* is what makes this a confirmed breach rather than a single suspicious request.
4. Surface the §5 exfiltration marker as the headline finding, with the earlier requests as supporting evidence of the attack's progression.

This structure (signatures → tiered severity → sequence correlation) is intentionally close to how a real SIEM correlation rule or EDR alert pipeline is built, so it should translate directly into actual code once the `EvidenceSource`/`LocalLabSource` implementation begins.
