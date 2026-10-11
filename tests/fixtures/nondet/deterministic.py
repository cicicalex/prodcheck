# Same data as set_order.py, but sorted: order no longer depends on the hash seed.
import os
tags = {"billing", "refund", "fraud", "shipping", "login", "account", "invoice", "tax"}
os.makedirs("out", exist_ok=True)
# Appends: if runs shared a directory, later runs would see earlier lines.
with open("out/result.txt", "a") as f:
    f.write(",".join(sorted(tags)) + "\n")
print("category:", sorted(tags)[0])
