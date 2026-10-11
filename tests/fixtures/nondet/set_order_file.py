# Stdout is constant; only the output file carries the set order.
import os
tags = {"billing", "refund", "fraud", "shipping", "login", "account", "invoice", "tax"}
os.makedirs("out", exist_ok=True)
with open("out/result.txt", "w") as f:
    f.write(",".join(tags) + "\n")
print("done")
