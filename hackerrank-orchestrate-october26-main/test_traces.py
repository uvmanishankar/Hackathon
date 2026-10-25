import os, re

log_dir = 'dataset/evidence/logs'
trace_keys = {}
trace_res = {}

for f in os.listdir(log_dir):
    p = os.path.join(log_dir, f)
    with open(p, 'r', encoding='utf-8', errors='ignore') as fp:
        for line in fp:
            m_tr = re.search(r'trace_id=["\']?([a-zA-Z0-9_-]+)', line)
            m_key = re.search(r'(?:lookup_key|match_key|owner_key|subject_key|correlation_key|subject_ref)=["\']?([^"\'\s]+)', line)
            m_res = re.search(r'resource_id=["\']?([^"\'\s]+)', line)
            if m_tr and m_key:
                tr = m_tr.group(1)
                k = m_key.group(1)
                trace_keys[tr] = k
            if m_tr and m_res:
                tr = m_tr.group(1)
                r = m_res.group(1)
                trace_res[tr] = r

matched = 0
for tr, k in trace_keys.items():
    if tr in trace_res:
        matched += 1
print(f"Total traces with keys: {len(trace_keys)}")
print(f"Total traces with resources: {len(trace_res)}")
print(f"Total correlated (trace -> key -> resource): {matched}")
