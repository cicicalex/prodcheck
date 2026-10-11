# Picks a category by iterating over a set: the real incident, reduced.
# With hash randomization the iteration order of str elements changes per
# process, so "the first matching category" changes too.
tags = {"billing", "refund", "fraud", "shipping", "login", "account", "invoice", "tax"}
for tag in tags:
    category = tag
    break
print("category:", category)
print("order:", ",".join(tags))
