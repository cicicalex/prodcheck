# Deterministic except for the wall-clock timestamp on the first line.
import datetime
print("generated at", datetime.datetime.now().isoformat())
print("total: 42")
