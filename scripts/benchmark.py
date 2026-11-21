"""Rough throughput check: python scripts/benchmark.py"""

import time

from bharatpii import Scanner
from bharatpii.fake import Faker

f = Faker(seed=1)
pii_line = f"Order shipped to Ravi, phone {f.phone()}, PAN {f.pan()}, delivered at gate 4 after 6pm, SKU-2231.\n"
log_line = "2024-11-21 10:30:00 INFO GET /api/orders/4521 200 12ms user=ravi region=ap-south-1\n"
prose = "The customer asked for a refund because the parcel arrived late and the box was damaged.\n"

scanner = Scanner()
for name, text in [
    ("logs (10% lines with PII)", (pii_line + log_line * 9) * 2000),
    ("prose without digits", prose * 20000),
]:
    t = time.perf_counter()
    n = len(scanner.scan(text))
    dt = time.perf_counter() - t
    print(f"{name:28} {len(text) / 1e6:.2f} MB  {n:5} matches  {dt:.2f}s  {len(text) / 1e6 / dt:6.2f} MB/s")

msg = pii_line
t = time.perf_counter()
for _ in range(5000):
    scanner.redact(msg)
print(f"{'redact one log message':28} {(time.perf_counter() - t) / 5000 * 1e6:.0f} us/message")
