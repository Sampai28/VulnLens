# DBSCAN clustering benchmark

**Question:** clustering ([`src/clustering.py`](../src/clustering.py)) runs inside
the analytics Lambda, which hard-stops at 15 minutes. Is the pure-Python DBSCAN
fast enough to stay in Lambda, or does it need to move to Fargate?

**Decision rule (from the benchmark plan):**

- medium input (50-80 findings) clusters in **< 30s** -> **keep in Lambda**
- medium input creeps toward **minutes** -> **move clustering to Fargate**

## How to run it

### 1. Locally (fast first signal)

From the `analytics/` directory:

```bash
python -m benchmarks.benchmark_dbscan
```

This times [`cluster_findings`](../src/clustering.py) on small / medium / large /
xlarge synthetic scans and prints a verdict against the 30s threshold. The DBSCAN
is pure Python and CPU-bound, so local timings predict Lambda behaviour up to a
constant CPU-speed factor (see note below).

### 2. In Lambda (authoritative measurement)

Lambda CPU scales with the configured memory, so the real number depends on the
function's memory setting. Measure it directly:

```bash
# from analytics/ -- package src/ + benchmarks/ at the zip root
zip -r bench.zip src benchmarks

aws lambda create-function \
  --function-name vulnlens-dbscan-bench \
  --runtime python3.12 \
  --handler benchmarks.benchmark_dbscan.handler \
  --timeout 900 \
  --memory-size 512 \
  --role <execution-role-arn> \
  --zip-file fileb://bench.zip

aws lambda invoke --function-name vulnlens-dbscan-bench --payload '{}' out.json
```

The handler logs one greppable line per size. Read them from CloudWatch Logs
Insights:

```
fields @timestamp, @message
| filter @message like /DBSCAN_BENCH/
| sort @timestamp asc
```

Re-run at a couple of memory sizes (e.g. 128 MB and 512 MB) to see how CPU
allotment moves the numbers, and check the `Duration` / `Billed Duration` and
`Max Memory Used` lines in the `REPORT` log entry.

When done: `aws lambda delete-function --function-name vulnlens-dbscan-bench`.

## Results

### Local (Python 3.14, dev machine, 3 repeats per size)

| input  | findings | themes | mean (ms) | max (ms) |
|--------|---------:|-------:|----------:|---------:|
| small  |       15 |      4 |       1.4 |     2.51 |
| medium |       65 |      8 |     10.67 |    10.83 |
| large  |      220 |      8 |     58.72 |     92.5 |
| xlarge |      500 |      8 |    217.33 |   219.28 |

### Lambda (CloudWatch `Duration`)

> Fill in after running step 2. Template:

| memory | input  | findings | duration (ms) | notes |
|--------|--------|---------:|--------------:|-------|
| 512 MB | medium |       65 |       14.41   |       |
| 512 MB | large  |      220 |       188.2   |       |
| 128 MB | medium |       65 |       69.29   |       |

## Decision

**Keep DBSCAN clustering in Lambda.**

Medium scans (65 findings) cluster in **~11 ms** locally — three orders of
magnitude under the 30s threshold. The neighbour search is O(n²), but the
constant is tiny: even a 500-finding stress scan finishes in ~0.2s locally, and
500 findings is already well beyond a realistic single-file scan.

Lambda's CPU is slower than a dev machine (CPU scales with memory; a 128 MB
function gets a fraction of a vCPU, roughly 5-12x slower). Applying that worst
case to the medium result gives ~60-130 ms — still far under 30s. There is no
case in normal operation where clustering approaches the 15-minute timeout, so
the Fargate migration is **not** warranted.

**Revisit if** scans routinely exceed ~2,000 findings (n² growth would put that
in the multi-second range at low memory), in which case the cheaper fix is
bumping Lambda memory before reaching for Fargate.
