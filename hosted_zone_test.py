

test = "user.dev.gt3.ess.barracuddanetworks.com"

zones = [
  "ess.barracudanetworks.com.",
  "barracudanetworks.com",
  "gt3.ess.barracudanetworks.com"
]

def domain_split(domain, zones):
  if domain == "":
    return None
  elif domain in zones:
    return domain
  else:
    return domain_split( '.'.join(domain.split('.')[1:]), zones )

print(domain_split(test, zones))
