"""
Ghost Data Still Exists -- deletion-audit agent.

    python code/main.py          # audits dataset/deletion_requests.csv -> output.csv (+ code/evaluation/usage_report.md)
    python code/main.py --eval   # scores case, step, sequence, evidence, and sample account-link accuracy

Pipeline (deterministic core, optional LLM only for ambiguous request intent):
  1. identity   : current + historical email / phone / user_id / email hash
  2. evidence   : logs, JSON/SQLite exports, handover text, PDFs, and locally OCR'd screenshot rows with source provenance
  3. linking    : a record belongs to the user if any observation carries one of the user's identifiers; records with no identifier
                  (deleted accounts, anonymized analytics) are attached through deletion-worker activity (see link_* functions)
  4. state      : latest observation at/before audit_at decides the state of each record; reported_status is never trusted
  5. policy     : deletion_rules.csv -> finding / remediation / verification operations; steps sorted exactly as the spec requires
Optional: pip install groq  +  GROQ_API_KEY  -> an LLM decides only requests the keyword rules cannot classify.
"""
from __future__ import annotations

import csv, hashlib, json, os, re, shutil, sqlite3, subprocess, sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"
USAGE_REPORT = Path(__file__).resolve().parent / "evaluation" / "usage_report.md"
MISMATCH_REPORT = Path(__file__).resolve().parent / "evaluation" / "sample_mismatch_report.md"
LLM_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")   # only used for ambiguous intent
SLACK_H = 1.0   # deletion actions may land up to this long after reported_at
DEBUG_LINKING = '--debug-linking' in sys.argv
WRITE_MISMATCH_REPORT = '--mismatch-report' in sys.argv

# --------------------------------------------------------------------------- constants
OPS = ['REPORT_REMAINING_RECORD', 'REPORT_EXPOSED_PII', 'REPORT_ACTIVE_DATA_FLOW', 'REPORT_RESTORE_RISK',
       'DISABLE_DATA_FLOW', 'BLOCK_RESTORE', 'DELETE_RECORD', 'REDACT_RECORD', 'ANONYMIZE_RECORD',
       'VERIFY_RECORD_ABSENT', 'VERIFY_RECORD_PRESENT', 'VERIFY_RECORD_REDACTED', 'VERIFY_RECORD_ANONYMIZED',
       'VERIFY_DATA_FLOW_DISABLED', 'VERIFY_RESTORE_BLOCKED']
STATE = dict(zip(OPS, ['PRESENT', 'PRESENT', 'ACTIVE', 'ACTIVE', 'DISABLED', 'BLOCKED', 'ABSENT', 'REDACTED', 'ANONYMIZED',
                       'ABSENT', 'PRESENT', 'REDACTED', 'ANONYMIZED', 'DISABLED', 'BLOCKED']))
PHASE_OF = {o: ('FINDING' if i < 4 else 'REMEDIATION' if i < 9 else 'VERIFICATION') for i, o in enumerate(OPS)}
PHASE_NO = {'FINDING': 0, 'REMEDIATION': 1, 'VERIFICATION': 2}
SYSTEM = {'account': 'account_service', 'search': 'search_service', 'analytics': 'analytics_platform', 'support': 'support_platform',
          'export': 'export_service', 'data_flow': 'integration_service', 'backup': 'backup_service', 'audit_record': 'security_service',
          'tombstone': 'identity_service', 'cache': 'cache_service', 'email_delivery': 'email_delivery_service',
          'marketing': 'marketing_platform', 'legal_hold': 'legal_service'}
DELETE_EVENTS = {'DELETE_RECORD', 'ANONYMIZE_RECORD', 'REDACT_RECORD', 'DISABLE_DATA_FLOW', 'BLOCK_RESTORE'}
RESULT_OF = {'COMPLETE': 'SUCCESS', 'PARTIALLY_COMPLETE': 'PARTIAL', 'NOT_STARTED': 'FAILED'}

RID = re.compile(r'\b((?:account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|cache|email_delivery|marketing|legal_hold)_[0-9]+)\b')
OCR_RID = re.compile(r'\b(account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|cache|email_delivery|marketing|legal_hold)[_ .-]*(\d{3,})\b', re.I)
KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
USERREF = re.compile(r'\buser_?\s?(\d+)\b', re.I)


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace('Z', '+00:00'))


def prefix(rid: str) -> str:
    return rid.rsplit('_', 1)[0]


def norm_phone(p) -> str:
    return re.sub(r'\D', '', p or '')


def _clean(v):
    if v is None:
        return None
    v = str(v).strip().strip('"')
    return None if v.lower() in ('null', 'none', '') else v


# --------------------------------------------------------------------------- evidence parsers -> observations
# observation = dict(file, t, rid, attrs{lowercase key: str|None}, snap)
def parse_log(path, fid):
    """key=value lines and '<ts> {json}' lines. Lines of one trace_id are merged (the lookup key is on a different line than the result)."""
    traces, order = {}, []
    for line in path.read_text(errors='replace').splitlines():
        m = re.match(r'(\d{4}-\d\d-\d\dT[\d:]+Z)\s+(.*)', line)
        if not m:
            continue
        t, rest = m.groups()
        if rest.lstrip().startswith('{'):
            try:
                kv = {k.lower(): _clean(v) for k, v in json.loads(rest).items()}
            except Exception:
                continue
        else:
            kv = {k.lower(): _clean(v) for k, v in KV.findall(rest)}
        key = kv.get('trace_id') or kv.get('resource_id') or f'L{len(order)}'
        if key not in traces:
            traces[key] = {'t': t, 'attrs': {}}
            order.append(key)
        traces[key]['t'] = t
        for k, v in kv.items():
            if v is not None or k not in traces[key]['attrs']:
                traces[key]['attrs'][k] = v
    return [dict(file=fid, t=traces[k]['t'], rid=traces[k]['attrs']['resource_id'], attrs=traces[k]['attrs'])
            for k in order if traces[k]['attrs'].get('resource_id')]


def parse_txt(text, fid):
    """handover sheet:  ts | system | resource_id | CATEGORY | STATE | subject"""
    out = []
    for line in text.splitlines():
        p = [x.strip() for x in line.lstrip('- ').split('|')]
        if len(p) >= 5 and RID.fullmatch(p[2]):
            out.append(dict(file=fid, t=p[0], rid=p[2], attrs=dict(system=p[1], category=p[3], state=p[4], subject=p[5] if len(p) > 5 else None)))
    return out


def _flat(d, out=None):
    out = {} if out is None else out
    for k, v in d.items():
        if isinstance(v, dict):
            _flat(v, out)
        elif not isinstance(v, list):
            out[k.lower()] = _clean(v)
    return out


def parse_json(path, fid):
    data = json.loads(path.read_text(errors='replace'))
    out = []

    def walk(node, ctx):
        if isinstance(node, dict):
            if isinstance(node.get('resource_id'), str):
                a = dict(ctx)
                a.update(_flat(node))
                out.append(dict(file=fid, t=a.get('observed_at') or a.get('captured_at') or a.get('exported_at'), rid=node['resource_id'], attrs=a))
                return
            c = dict(ctx)
            for k, v in node.items():
                if isinstance(v, (str, int, float)) and k in ('captured_at', 'data_store', 'collection', 'exported_at', 'region'):
                    c[k.lower()] = _clean(v)
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    c2 = dict(c)
                    if k.endswith('_service') or k.endswith('_platform'):
                        c2['data_store'] = k
                    walk(v, c2)
        elif isinstance(node, list):
            for x in node:
                walk(x, ctx)

    walk(data, {'exported_at': data.get('exported_at') if isinstance(data, dict) else None})
    return out


def parse_sql(path, fid, captured_at):
    """SQLite snapshot. Every row of every table (primary, replicas, failover...) is an observation; *_json columns are expanded."""
    txt = path.read_text(errors='replace')
    con = sqlite3.connect(':memory:')
    try:
        con.executescript(txt)
    except Exception:
        return []
    con.row_factory = sqlite3.Row
    out = []
    for (tbl,) in con.execute("select name from sqlite_master where type='table'").fetchall():
        for r in con.execute(f'select * from "{tbl}"'):
            d = {k.lower(): _clean(r[k]) for k in r.keys()}
            for jk in [k for k in d if k.endswith('_json') and d[k]]:
                try:
                    d.update(_flat(json.loads(d[jk])))
                except Exception:
                    pass
            if d.get('resource_id'):
                d['table'] = tbl
                out.append(dict(file=fid, t=captured_at, rid=d['resource_id'], attrs=d, snap=captured_at))
    return out


def pdf_text(path) -> str:
    if shutil.which('pdftotext'):
        return subprocess.run(['pdftotext', '-layout', str(path), '-'], capture_output=True, text=True).stdout
    try:
        import pdfplumber
        with pdfplumber.open(path) as pdf:
            return '\n'.join(p.extract_text() or '' for p in pdf.pages)
    except Exception:
        return ''


def parse_pdf(path, fid, captured_at):
    """Statements / attachments: every resource id in the document is tagged with the emails and user ids printed in it."""
    text = pdf_text(path)
    ids = {m.lower() for m in EMAIL.findall(text)} | {'user_' + n for n in USERREF.findall(text)}
    return [dict(file=fid, t=captured_at, rid=r, snap=captured_at,
                 attrs=dict(docname=path.stem.lower(), **{f'id{i}': v for i, v in enumerate(sorted(ids))}))
            for r in sorted(set(RID.findall(text)))]


def parse_image(path, fid, captured_at, source_path):
    """OCR resource rows and keep identity only when it appears in that same visual row."""
    import pytesseract
    from PIL import Image, ImageOps
    from pytesseract import Output

    executable = os.environ.get('TESSERACT_CMD') or shutil.which('tesseract')
    if not executable:
        for candidate in (
            Path(r'C:\Program Files\Tesseract-OCR\tesseract.exe'),
            Path(r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe'),
        ):
            if candidate.is_file():
                executable = str(candidate)
                break
    if not executable:
        raise RuntimeError('Tesseract OCR executable not found; set TESSERACT_CMD or install Tesseract')
    pytesseract.pytesseract.tesseract_cmd = executable

    with Image.open(path) as source:
        raw = source.copy()
        image = ImageOps.autocontrast(source.convert('L')).resize(
            (source.width * 3 // 2, source.height * 3 // 2),
            Image.Resampling.LANCZOS,
        )
        binary = image.point(lambda pixel: 255 if pixel >= 150 else 0)

    observations = {}
    for processed in (raw, binary):
        data = pytesseract.image_to_data(processed, config='--psm 6', output_type=Output.DICT)
        words = []
        for index, text in enumerate(data['text']):
            text = text.strip()
            try:
                confidence = float(data['conf'][index])
            except (TypeError, ValueError):
                continue
            if text and confidence >= 20:
                words.append((
                    data['left'][index],
                    data['top'][index] + data['height'][index] / 2,
                    text,
                    confidence,
                ))
        words.sort(key=lambda word: (word[1], word[0]))

        rows = []
        for word in words:
            row = next((candidate for candidate in reversed(rows)
                        if abs(candidate['center_y'] - word[1]) <= 12), None)
            if row is None:
                row = {'center_y': word[1], 'words': []}
                rows.append(row)
            row['words'].append(word)

        for row in rows:
            row_words = sorted(row['words'], key=lambda word: word[0])
            text_parts, spans, offset = [], [], 0
            for _, _, word, confidence in row_words:
                if text_parts:
                    offset += 1
                start = offset
                text_parts.append(word)
                offset += len(word)
                spans.append((start, offset, confidence))
            row_text = ' '.join(text_parts)

            def span_confidence(start, end):
                scores = [score for left, right, score in spans if left < end and right > start]
                return min(scores) if scores else 0

            emails = {
                match.group().lower()
                for match in EMAIL.finditer(row_text)
                if span_confidence(*match.span()) >= 35
            }
            user_ids = {
                'user_' + match.group(1)
                for match in USERREF.finditer(row_text)
                if span_confidence(*match.span()) >= 35
            }
            owners = {}
            if len(user_ids) == 1:
                owners['user_id'] = next(iter(user_ids))
            elif not user_ids and len(emails) == 1:
                owners['email'] = next(iter(emails))

            for match in OCR_RID.finditer(row_text):
                confidence = span_confidence(*match.span())
                if confidence < 40:
                    continue
                rid = f'{match.group(1).lower()}_{match.group(2)}'
                attrs = {
                    **owners,
                    'ocr_text': row_text,
                    'ocr_confidence': str(round(confidence)),
                    'source_image': path.name,
                    'source_path': source_path,
                    'captured_at': captured_at,
                }
                key = (rid, owners.get('user_id'), owners.get('email'))
                observation = dict(file=fid, t=captured_at, rid=rid, snap=captured_at, attrs=attrs)
                previous = observations.get(key)
                if not previous or confidence > float(previous['attrs']['ocr_confidence']):
                    observations[key] = observation

    return list(observations.values())


def parse_all(ds, manifest):
    obs, image_count, image_observation_count, unrecognized_images = [], 0, 0, 0
    for ev in manifest:
        p, fid, cap, suf = ds / ev['file_path'], ev['file_id'], ev['captured_at'], Path(ev['file_path']).suffix.lower()
        try:
            o = (parse_log(p, fid) if suf == '.log' else parse_json(p, fid) if suf == '.json' else parse_sql(p, fid, cap) if suf == '.sql'
                 else parse_txt(p.read_text(errors='replace'), fid) if suf == '.txt' else parse_pdf(p, fid, cap) if suf == '.pdf'
                 else parse_image(p, fid, cap, ev['file_path']) if suf in {'.png', '.jpg', '.jpeg', '.webp'} else [])
            if suf in {'.png', '.jpg', '.jpeg', '.webp'}:
                image_count += 1
                image_observation_count += len(o)
                unrecognized_images += not o
        except Exception as e:
            print(f'  warning: could not parse {ev["file_path"]}: {e}', file=sys.stderr)
            o = []
        for x in o:
            x['t'] = x['t'] or cap
            x.setdefault('snap', cap)
        obs += o
    if image_count:
        print(
            f'  image evidence OCR: processed {image_count} files, '
            f'extracted {image_observation_count} resource observations; '
            f'{unrecognized_images} images had no confident resource IDs',
            file=sys.stderr,
        )
    return obs


# --------------------------------------------------------------------------- data + identity
class Data:
    def __init__(self, ds: Path):
        L = lambda n: list(csv.DictReader(open(ds / n, encoding='utf-8')))
        self.ident, self.audit = L('user_identities.csv'), L('user_audit_log.csv')
        self.activity, self.manifest = L('system_activity.csv'), L('evidence_files.csv')
        self.by_id = {i['user_id']: i for i in self.ident}
        self.by_email = {i['email'].lower(): i for i in self.ident}
        self.by_hash = {i['email_hash']: i for i in self.ident if i['email_hash']}
        self.hist_email = {a['old_value'].lower(): a['user_id'] for a in self.audit if a['field_name'] == 'email'}
        self.hist = {}
        for a in self.audit:
            self.hist.setdefault(a['user_id'], []).append(a)
        self.obs = parse_all(ds, self.manifest)
        self.cap = {m['file_id']: m['captured_at'] for m in self.manifest}
        self.act_by_rid = {}
        for a in self.activity:
            self.act_by_rid.setdefault(a['resource_id'], []).append(a)
        self.claimed, self.act_link = {}, {}

    def resolve(self, email: str):
        e = email.lower().strip()
        u = self.by_email.get(e) or self.by_id.get(self.hist_email.get(e, '')) or self.by_hash.get(hashlib.sha256(e.encode()).hexdigest())
        if not u:
            return None
        ids = {'user_id': u['user_id'], 'emails': {u['email'].lower(), e}, 'phones': {norm_phone(u['phone'])}, 'hashes': {u['email_hash']}}
        for h in self.hist.get(u['user_id'], []):
            if h['field_name'] == 'email':
                ids['emails'].add(h['old_value'].lower())
            elif h['field_name'] == 'phone':
                ids['phones'].add(norm_phone(h['old_value']))
        ids['phones'].discard('')
        return ids


def matches(ob, ids) -> bool:
    for k, v in ob['attrs'].items():
        if not v or k == 'resource_id':
            continue
        lv = str(v).lower()
        if lv == ids['user_id'] or lv in ids['emails'] or str(v) in ids['hashes']:
            return True
        if k in ('phone', 'requester_phone', 'owner_phone') and norm_phone(v) in ids['phones']:
            return True
        if k in ('message_text', 'message_excerpt', 'body', 'note', 'details') and any(e in lv for e in ids['emails']):
            return True
    return False


def resource_owner_index(D: Data):
    owners = {}
    for observation in D.obs:
        attrs = observation['attrs']
        for key in ('email', 'requester_email', 'customer_email', 'owner_email', 'subject', 'lookup_key'):
            value = attrs.get(key)
            if value and '@' in str(value):
                ids = D.resolve(str(value))
                if ids:
                    owners.setdefault(observation['rid'], set()).add(ids['user_id'])
        for key in ('user_id', 'subject_reference', 'customer_reference'):
            value = attrs.get(key)
            if value and str(value).lower().startswith('user') and str(value).lower() in D.by_id:
                owners.setdefault(observation['rid'], set()).add(str(value))
    return owners


# --------------------------------------------------------------------------- linking records that carry no identifier
def link_by_activity(D: Data, cases):
    """Pre-pass over ALL cases: (1) exclusive identifier claims; (2) strict activity linking (exactly one case could own the record);
    (3) account alignment. A record with no identifier is a candidate for a case when it sits in an evidence file that also holds
    that case's identified records AND a deletion-worker action touched it inside [requested_at, reported_at + slack]."""
    infos = []
    for c in cases:
        ids = D.resolve(c['email'])
        if ids:
            infos.append((c, ids))
    resource_owners = resource_owner_index(D)
    ocr_resources = {o['rid'] for o in D.obs if 'ocr_confidence' in o['attrs']}
    unattributed_analytics = {
        o['rid'] for o in D.obs
        if prefix(o['rid']) == 'analytics'
        and str(o['attrs'].get('subject', '')).lower() == 'no direct identifier'
    }
    files_of = {}
    for o in D.obs:
        for c, ids in infos:
            if matches(o, ids):
                D.claimed.setdefault(o['rid'], set()).add(ids['user_id'])
                files_of.setdefault(ids['user_id'], set()).add(o['file'])
    file_rids = {}
    for o in D.obs:
        file_rids.setdefault(o['file'], set()).add(o['rid'])
    for rid, acts in D.act_by_rid.items():
        if rid in D.claimed:
            continue
        if rid in ocr_resources:
            continue
        if rid in unattributed_analytics and not resource_owners.get(rid):
            continue
        acts = [a for a in acts if a['source_system'] == 'deletion_worker' and a['event_type'] in DELETE_EVENTS]
        if not acts:
            continue
        elig = set()
        for c, ids in infos:
            if resource_owners.get(rid, set()) - {ids['user_id']}:
                continue
            lo, hi = ts(c['requested_at']), ts(c['reported_at']) + timedelta(hours=SLACK_H)
            if any(rid in file_rids[f] for f in files_of.get(ids['user_id'], ())) and any(lo <= ts(a['event_time']) <= hi for a in acts):
                elig.add(ids['user_id'])
        if len(elig) == 1:
            D.act_link.setdefault(next(iter(elig)), set()).add(rid)
    link_accounts(D, infos, resource_owners)


def link_accounts(D: Data, infos, resource_owners=None):
    """Link deleted accounts only when status and time-window candidates are unambiguous."""
    resource_owners = resource_owners if resource_owners is not None else resource_owner_index(D)
    have = {u for rid, owners in D.claimed.items() if prefix(rid) == 'account' for u in owners}
    cand = [(c, ids) for c, ids in infos if ids['user_id'] not in have and c['reported_status'] in RESULT_OF]
    taken = {r for s in D.act_link.values() for r in s}
    acts = {a['resource_id']: a for a in D.activity if a['source_system'] == 'deletion_worker' and a['event_type'] == 'DELETE_RECORD'
            and a['target_system'] == 'account_service' and a['resource_id'] not in D.claimed and a['resource_id'] not in taken}
    groups = {}
    for rid, a in acts.items():
        t = ts(a['event_time'])
        e = tuple(sorted(i for i, (c, _) in enumerate(cand) if RESULT_OF[c['reported_status']] == a['reported_result']
                         and ts(c['requested_at']) <= t <= ts(c['reported_at']) + timedelta(hours=SLACK_H)))
        if e:
            groups.setdefault(e, []).append(rid)
    if DEBUG_LINKING:
        print("\n[ACCOUNT LINK DEBUG]")
        for e, rids in groups.items():
            print("Candidate case indexes:", e)
            print("Candidate resources:", rids)
            print(
                "Candidate cases:",
                [
                    {
                        "case_id": cand[i][0]["case_id"],
                        "user_id": cand[i][1]["user_id"],
                        "status": cand[i][0]["reported_status"],
                    }
                    for i in e
                ],
            )
    for e, rids in groups.items():
        if len(e) != 1 or len(rids) != 1:
            continue
        case_index = e[0]
        resource_id = rids[0]
        case_ids = cand[case_index][1]
        user_id = case_ids['user_id']
        if resource_owners.get(resource_id, set()) - {user_id}:
            continue
        D.act_link.setdefault(user_id, set()).add(resource_id)


# --------------------------------------------------------------------------- state of a record + policy (deletion_rules.csv)
IDKEYS = ('email', 'requester_email', 'customer_email', 'owner_email', 'requester_phone', 'phone', 'email_hash', 'full_name',
          'requester_name', 'display_name')
T = ('true', '1', 'yes')


def state_of(ob):
    """-> (data_category, state). state: PRESENT ABSENT IDENTIFIABLE ANONYMIZED REDACTED ACTIVE DISABLED BLOCKED"""
    a, rid = ob['attrs'], ob['rid']
    p = prefix(rid)
    cat, st = (a.get('category') or '').upper(), (a.get('state') or a.get('result') or a.get('status') or '').upper()
    has_id = any(a.get(k) for k in IDKEYS)
    if cat:   # handover sheet states the category and state explicitly
        m = {'NOT_FOUND': 'ABSENT', 'FOUND': 'PRESENT', 'IDENTIFIABLE': 'IDENTIFIABLE', 'ANONYMIZED': 'ANONYMIZED', 'REDACTED': 'REDACTED',
             'ACTIVE': 'ACTIVE', 'DISABLED': 'DISABLED', 'BLOCKED': 'BLOCKED'}
        return cat, m.get(st, 'PRESENT')
    if p == 'account':
        if a.get('account_status', '').upper() in ('DELETED', 'TOMBSTONE'):
            return 'ACCOUNT_TOMBSTONE', 'IDENTIFIABLE' if has_id else 'REDACTED'
        gone = a.get('http_status') == '404' or a.get('rows') == '0' or a.get('result', '').upper() == 'NOT_FOUND' or \
            ('profile' in a and not has_id and a.get('status_code') == '404')
        return 'USER_PROFILE', 'ABSENT' if gone and 'table' not in a else 'PRESENT'
    if p == 'search':
        miss = a.get('result', '').lower() in ('miss', 'not_found') or a.get('total_hits') == '0'
        return 'SEARCH_INDEX_ENTRY', 'ABSENT' if miss else 'PRESENT'
    if p == 'analytics':
        if 'email_opt_in' in a or 'contact' in a.get('event', ''):   # a marketing contact living inside the analytics system
            return 'MARKETING_PROFILE', 'ABSENT' if a.get('rows') == '0' else 'PRESENT'
        return 'ANALYTICS_PROFILE', 'IDENTIFIABLE' if has_id else 'ANONYMIZED'
    if p == 'support':
        if str(a.get('marker_found', '')).lower() == 'false' and a.get('rows') != '0':   # legacy replica still holds it, no deletion marker
            return 'SUPPORT_ATTACHMENT', 'PRESENT'
        if a.get('matched_value'):                                                       # PII scan hit
            return 'SUPPORT_MESSAGE', 'IDENTIFIABLE'
        if a.get('docname'):
            return ('SUPPORT_ATTACHMENT', 'PRESENT') if 'attach' in a['docname'] else ('SUPPORT_MESSAGE', 'IDENTIFIABLE')
        c = 'SUPPORT_ATTACHMENT' if any('attach' in k for k in a) or 'attachment' in str(a.get('message_excerpt', '')).lower() else 'SUPPORT_MESSAGE'
        txt_id = bool(EMAIL.search(str(a.get('message_text') or '')))
        return c, 'IDENTIFIABLE' if (has_id or txt_id) else 'REDACTED'
    if p == 'export':
        gone = a.get('status', '').lower() in ('deleted', 'absent', 'not_found') or a.get('result', '').lower() == 'not_found'
        return 'USER_EXPORT', 'ABSENT' if gone else 'PRESENT'
    if p == 'data_flow':
        en = str(a.get('enabled', '')).lower() in T or st == 'ACTIVE' or (str(a.get('scheduler_registered', '')).lower() in T and 'enabled' not in a)
        return 'DATA_FLOW', 'ACTIVE' if en else 'DISABLED'
    if p == 'backup':
        if 'restore_allowed' in a:
            ra = str(a['restore_allowed']).lower() in T
        elif 'deletion_block' in a:
            ra = str(a['deletion_block']).lower() not in T and str(a.get('eligible', 'true')).lower() in T
        else:
            ra = False
        return 'BACKUP_ARCHIVE', 'ACTIVE' if ra else 'BLOCKED'
    if p == 'audit_record':
        return 'SECURITY_AUDIT_LOG', 'PRESENT'
    if p == 'tombstone':
        return 'ACCOUNT_TOMBSTONE', 'IDENTIFIABLE' if has_id else 'REDACTED'
    if p == 'cache':
        return 'CACHE_ENTRY', 'PRESENT'
    if p == 'marketing':
        return 'MARKETING_PROFILE', 'PRESENT'
    if p == 'email_delivery':
        return 'EMAIL_DELIVERY_LOG', 'IDENTIFIABLE' if has_id else 'REDACTED'
    if p == 'legal_hold':
        return 'LEGAL_HOLD_RECORD', 'PRESENT'
    return 'UNKNOWN', 'PRESENT'


def plan_for(cat, st):
    """deletion_rules.csv -> (finding, remediation, verification) operation for one record"""
    DEL = ('REPORT_REMAINING_RECORD', 'DELETE_RECORD', 'VERIFY_RECORD_ABSENT')
    if cat in ('USER_PROFILE', 'SEARCH_INDEX_ENTRY', 'CACHE_ENTRY', 'USER_EXPORT', 'MARKETING_PROFILE', 'SUPPORT_ATTACHMENT'):   # rules 01-04, 06, 09, 10
        return DEL if st == 'PRESENT' else (None, None, 'VERIFY_RECORD_ABSENT')
    if cat in ('ANALYTICS_PROFILE', 'PRODUCT_TELEMETRY'):                                                                      # rules 07, 08
        return ('REPORT_EXPOSED_PII', 'ANONYMIZE_RECORD', 'VERIFY_RECORD_ANONYMIZED') if st == 'IDENTIFIABLE' else (None, None, 'VERIFY_RECORD_ANONYMIZED')
    if cat in ('SUPPORT_MESSAGE', 'EMAIL_DELIVERY_LOG', 'ACCOUNT_TOMBSTONE'):                                                  # rules 05, 11, 15
        return ('REPORT_EXPOSED_PII', 'REDACT_RECORD', 'VERIFY_RECORD_REDACTED') if st == 'IDENTIFIABLE' else (None, None, 'VERIFY_RECORD_REDACTED')
    if cat == 'DATA_FLOW':
        return ('REPORT_ACTIVE_DATA_FLOW', 'DISABLE_DATA_FLOW', 'VERIFY_DATA_FLOW_DISABLED') if st == 'ACTIVE' else (None, None, 'VERIFY_DATA_FLOW_DISABLED')
    if cat == 'BACKUP_ARCHIVE':                                                                                                # rule 14: keep, block restore
        return ('REPORT_RESTORE_RISK', 'BLOCK_RESTORE', 'VERIFY_RESTORE_BLOCKED') if st == 'ACTIVE' else (None, None, 'VERIFY_RESTORE_BLOCKED')
    if cat in ('SECURITY_AUDIT_LOG', 'LEGAL_HOLD_RECORD'):                                                                     # rules 12, 13: retain
        return (None, None, 'VERIFY_RECORD_PRESENT')
    return (None, None, None)


# --------------------------------------------------------------------------- request intent
DEL_RE = re.compile(r"delet|erase|erasure|remove (?:my|the|all)|close (?:my|the)|closure|forget|wipe|purge|supprim|efface|elimin|borr|apag|exclu|lösch|cancel|"
                    r"삭제|제거|削除|消去|删除|刪除|注销|удал|حذف|account.*(?:closed|closing)", re.I)
KEEP_RE = re.compile(r"(?:keep|leave)\b.{0,40}\b(?:account|profile|active|as it is|in place)|download|copy of|portable|replace it|out of date|"
                     r"change the (?:email|address|phone|number)|update (?:my|the)|continue using|invoices? for my records", re.I)
NEG_RE = re.compile(r"(?:don'?t|do not|never|without)\s+(?:\w+\s+)?(?:delet|remov|chang|clos)|(?:keep|leave)\b.{0,30}\b(?:account|profile|active|as it is|in place)|"
                    r"still use (?:it|the account)|continue using|not (?:asking for|a request (?:to|for))\s+(?:\w+\s+)?(?:delet|eras|remov)|"
                    r"marketing lists? only|promotional emails|unsubscribe|opt.?out|without removing", re.I)


def is_deletion_request(text, llm=None) -> bool:
    if NEG_RE.search(text):
        return False
    if DEL_RE.search(text):
        return True
    if KEEP_RE.search(text):
        return False
    return llm(text) if llm else True


class LLM:
    """Optional: decides only requests that match neither keyword family. Tracks usage for evaluation/usage_report.md."""
    def __init__(self):
        self.calls = self.tin = self.tout = 0
        from groq import Groq
        self.client = Groq(api_key=os.environ['GROQ_API_KEY'])

    def __call__(self, text) -> bool:
        r = self.client.chat.completions.create(model=LLM_MODEL, temperature=0, max_tokens=5, messages=[
            {'role': 'system', 'content': 'Does the customer ask for their account or personal data to be DELETED? Answer only YES or NO.'},
            {'role': 'user', 'content': text}])
        self.calls += 1
        self.tin += r.usage.prompt_tokens
        self.tout += r.usage.completion_tokens
        return r.choices[0].message.content.strip().upper().startswith('Y')


# --------------------------------------------------------------------------- the audit
def audit_case(D: Data, case, llm=None):
    if not is_deletion_request(case['request_text'], llm):
        return 'NOT_APPLICABLE', []
    ids = D.resolve(case['email'])
    if not ids:
        return 'INCOMPLETE', []
    audit_at = ts(case['audit_at'])
    obs = [o for o in D.obs if ts(o['t'] or D.cap[o['file']]) <= audit_at]
    if DEBUG_LINKING and case['case_id'] in {'case_03', 'case_04', 'case_18', 'case_20', 'case_23'}:
        print(f"\n[TRACE] {case['case_id']} audit_at={case['audit_at']}")
        print(f"[TRACE] Resolved emails: {sorted(ids['emails'])}")
        print(f"[TRACE] Resolved phones: {sorted(ids['phones'])}")
        for o in obs:
            if matches(o, ids):
                print(
                    f"[TRACE] MATCH rid={o['rid']} "
                    f"file={o['file']} time={o['t']} "
                    f"attrs={o['attrs']}"
                )
    request_start = ts(case['requested_at'])
    request_end = ts(case['reported_at']) + timedelta(hours=SLACK_H)
    directly_claimed_accounts = {
        rid
        for rid, owners in D.claimed.items()
        if prefix(rid) == 'account' and owners == {ids['user_id']}
        and any(
            a['source_system'] == 'deletion_worker'
            and a['event_type'] == 'DELETE_RECORD'
            and a['target_system'] == 'account_service'
            and request_start <= ts(a['event_time']) <= request_end
            for a in D.act_by_rid.get(rid, [])
        )
    }
    direct_matches = {o['rid'] for o in obs if matches(o, ids)}
    linked = (
        {rid for rid in direct_matches if prefix(rid) != 'account'}
        | D.act_link.get(ids['user_id'], set())
        | directly_claimed_accounts
    )
    if DEBUG_LINKING and case['case_id'] in {
        'case_03', 'case_04', 'case_11', 'case_18',
        'case_20', 'case_23', 'case_32'
    }:
        print(f"\n[DEBUG] Case: {case['case_id']}")
        print(f"[DEBUG] User ID: {ids['user_id']}")
        print(f"[DEBUG] Linked resources: {sorted(linked)}")
    if not any(prefix(r) == 'account' for r in linked):   # hand-numbered tutorial cases: account_001 <-> user_01
        m = re.fullmatch(r'user_0*(\d+)', ids['user_id'])
        cand = 'account_%03d' % int(m.group(1)) if m else None
        if cand and any(a['source_system'] == 'deletion_worker' and ts(a['event_time']) <= audit_at for a in D.act_by_rid.get(cand, [])):
            linked.add(cand)
    by_rid = {}
    for o in obs:
        if o['rid'] in linked:
            by_rid.setdefault(o['rid'], []).append(o)
    for rid in linked:
        if rid not in by_rid:   # known only from the deletion activity: gone from every snapshot; cite the latest snapshot that could have shown it
            acts = [a for a in D.act_by_rid.get(rid, []) if ts(a['event_time']) <= audit_at]
            if acts:
                user_evidence = sorted(
                    (ts(D.cap[o['file']]), o['file'])
                    for o in obs if matches(o, ids)
                )
                snapshots = sorted(
                    (ts(m['captured_at']), m['file_id'])
                    for m in D.manifest
                    if m['file_path'].endswith(('.sql', '.json'))
                    and ts(m['captured_at']) <= audit_at
                )
                cite = (
                    user_evidence[-1][1] if user_evidence
                    else snapshots[-1][1] if snapshots
                    else ''
                )
                by_rid[rid] = [dict(file=cite, t=acts[-1]['event_time'], rid=rid, attrs=dict(http_status='404'))]
    recs = []
    for rid, lst in by_rid.items():
        lst.sort(key=lambda o: (ts(o['t']), ts(D.cap.get(o['file'], o['t']))))
        cat, st = state_of(lst[-1])                                            # latest observation at audit_at decides the state
        same = [o for o in lst if state_of(o) == (cat, st)]
        cite = (same[0] if same else lst[-1])['file']                          # cite the earliest observation that already shows that state
        f, r, v = plan_for(cat, st)
        recs.append((rid, SYSTEM.get(prefix(rid), 'unknown'), f, r, v, cite))
        if DEBUG_LINKING and case['case_id'] in {
            'case_03', 'case_04', 'case_11', 'case_18',
            'case_20', 'case_23', 'case_32'
        }:
            print(
                f"[DEBUG] {rid}: "
                f"category={cat}, state={st}, "
                f"finding={f}, remediation={r}, "
                f"verification={v}, evidence={cite}"
            )
    incomplete = any(x[2] for x in recs)
    rows = []
    for rid, sy, f, r, v, cite in recs:
        if incomplete:   # findings cite evidence; remediation and future verification have an empty evidence_id
            if f: rows.append((f, sy, rid, cite))
            if r: rows.append((r, sy, rid, ''))
            if v: rows.append((v, sy, rid, ''))
        elif v:
            rows.append((v, sy, rid, cite))
    rows.sort(key=lambda x: (PHASE_NO[PHASE_OF[x[0]]], OPS.index(x[0]), x[1], x[2]))
    steps = [dict(step_no=i, phase=PHASE_OF[o], system_id=sy, resource_id=ri, operation=o, state=STATE[o], evidence_id=ev)
             for i, (o, sy, ri, ev) in enumerate(rows, 1)]
    return ('INCOMPLETE' if incomplete else 'COMPLETE'), steps


# --------------------------------------------------------------------------- run / evaluate
def load_cases():
    L = lambda n: list(csv.DictReader(open(DATASET / n, encoding='utf-8')))
    return L('deletion_requests.csv'), L('sample_deletion_requests.csv')


def make_llm():
    if os.environ.get('GROQ_API_KEY'):
        try:
            return LLM()
        except Exception as e:
            print(f'LLM disabled ({e})', file=sys.stderr)
    return None


def run():
    requests, samples = load_cases()
    D = Data(DATASET)
    link_by_activity(D, requests + samples)
    llm = make_llm()
    rows = []
    for c in requests:
        st, steps = audit_case(D, c, llm)
        rows.append(dict(case_id=c['case_id'], deletion_status=st, steps_json=json.dumps(steps, separators=(',', ':'), ensure_ascii=False)))
    rows.sort(key=lambda r: r['case_id'])
    with open(OUTPUT, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['case_id', 'deletion_status', 'steps_json'])
        w.writeheader()
        w.writerows(rows)
    from collections import Counter
    print(f'wrote {len(rows)} rows to {OUTPUT}; status counts: {dict(Counter(r["deletion_status"] for r in rows))}')
    calls, tin, tout = (llm.calls, llm.tin, llm.tout) if llm else (0, 0, 0)
    total_tokens = tin + tout
    total_cost = tin * 0.59e-6 + tout * 0.79e-6
    USAGE_REPORT.parent.mkdir(parents=True, exist_ok=True)
    USAGE_REPORT.write_text(
        "# Usage report (generated by code/main.py)\n\n"
        f"Final full-dataset run: {len(rows)} requests.\n\n"
        "The audit is deterministic Python. Groq is optional and is consulted only "
        "for request text that the deterministic intent rules cannot classify.\n\n"
        "| Provider | Model | Calls | Input tokens | Output tokens | Total tokens | "
        "Average tokens/request | Estimated total cost | Estimated cost/request |\n"
        "|---|---|---:|---:|---:|---:|---:|---:|---:|\n"
        f"| {'Groq' if llm else '-'} | {LLM_MODEL if llm else 'none (not used)'} | "
        f"{calls} | {tin} | {tout} | {total_tokens} | "
        f"{total_tokens / max(1, len(rows)):.2f} | ${total_cost:.4f} | "
        f"${total_cost / max(1, len(rows)):.6f} |\n"
        f"| **Overall** | - | {calls} | {tin} | {tout} | {total_tokens} | "
        f"{total_tokens / max(1, len(rows)):.2f} | ${total_cost:.4f} | "
        f"${total_cost / max(1, len(rows)):.6f} |\n\n"
        "Pricing assumption: $0.59 / 1M input tokens and $0.79 / 1M output "
        "tokens for Groq llama-3.3-70b-versatile; verify current rates."
    )


def evaluate():
    requests, samples = load_cases()
    D = Data(DATASET)
    link_by_activity(D, requests + samples)
    gold = {r['case_id']: r for r in csv.DictReader(open(DATASET / 'sample_output.csv', encoding='utf-8'))}
    key = lambda s: (s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state'])
    status_correct = exact_rows = exact_semantic_sequences = exact_step_arrays = 0
    tp = fp = fn = evidence_correct = evidence_total = 0
    account_correct = account_incorrect = account_abstained = 0
    field_correct = {field: 0 for field in ('step_no', 'phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id')}
    field_total = {field: 0 for field in field_correct}
    mismatch_cases = []
    for c in samples:
        st, steps = audit_case(D, c)
        g = gold[c['case_id']]
        gs = json.loads(g['steps_json'])
        A, B = {key(s) for s in steps}, {key(s) for s in gs}
        status_matches = st == g['deletion_status']
        semantic_sequence_matches = [key(s) for s in steps] == [key(s) for s in gs]
        full_steps_match = steps == gs
        status_correct += status_matches
        exact_rows += status_matches and full_steps_match
        exact_semantic_sequences += semantic_sequence_matches
        exact_step_arrays += full_steps_match
        tp += len(A & B)
        fp += len(A - B)
        fn += len(B - A)
        for position in range(max(len(steps), len(gs))):
            predicted_step = steps[position] if position < len(steps) else {}
            expected_step = gs[position] if position < len(gs) else {}
            for field in field_correct:
                if field in predicted_step or field in expected_step:
                    field_total[field] += 1
                    field_correct[field] += (
                        field in predicted_step and field in expected_step
                        and predicted_step[field] == expected_step[field]
                    )
        predicted_accounts = {s['resource_id'] for s in steps if prefix(s['resource_id']) == 'account'}
        expected_accounts = {s['resource_id'] for s in gs if prefix(s['resource_id']) == 'account'}
        correct_accounts = predicted_accounts & expected_accounts
        incorrect_accounts = predicted_accounts - expected_accounts
        abstained_accounts = expected_accounts - predicted_accounts
        account_correct += len(correct_accounts)
        account_incorrect += len(incorrect_accounts)
        account_abstained += len(abstained_accounts)
        gev = {key(s): s['evidence_id'] for s in gs}
        evidence_mismatches = []
        for s in steps:
            if key(s) in gev:
                evidence_total += 1
                evidence_correct += s['evidence_id'] == gev[key(s)]
                if s['evidence_id'] != gev[key(s)]:
                    evidence_mismatches.append(
                        (key(s), gev[key(s)], s['evidence_id'])
                    )
        if not status_matches or not full_steps_match:
            mismatch_cases.append({
                'case_id': c['case_id'],
                'expected_status': g['deletion_status'],
                'predicted_status': st,
                'missing': sorted(B - A),
                'extra': sorted(A - B),
                'evidence_mismatches': evidence_mismatches,
                'expected_steps': gs,
                'predicted_steps': steps,
            })
        if '-v' in sys.argv:
            for k in sorted(A - B): print(c['case_id'], 'EXTRA  ', k)
            for k in sorted(B - A): print(c['case_id'], 'MISSING', k)
            if incorrect_accounts or abstained_accounts:
                print(c['case_id'], 'ACCOUNT EXTRA VS EXPECTED', sorted(incorrect_accounts),
                      'ABSTAINED EXPECTED', sorted(abstained_accounts))
    n = len(samples)
    p, r = tp / max(1, tp + fp), tp / max(1, tp + fn)
    f1 = 2 * p * r / max(1e-9, p + r)
    print(f'case status accuracy : {status_correct}/{n} ({status_correct / max(1, n):.0%})')
    print(f'exact output-row accuracy: {exact_rows}/{n} ({exact_rows / max(1, n):.1%})')
    print(f'step precision       : {p:.2f} ({tp} TP, {fp} FP)')
    print(f'step recall          : {r:.2f} ({tp} TP, {fn} FN)')
    print(f'step F1              : {f1:.2f}')
    print(f'exact semantic step sequences: {exact_semantic_sequences}/{n}')
    print(f'exact full step arrays       : {exact_step_arrays}/{n}')
    print(f'evidence ID accuracy         : {evidence_correct}/{evidence_total} on matched steps')
    print('step field accuracy (position-aligned):')
    for field in field_correct:
        print(f'  {field:12}: {field_correct[field]}/{field_total[field]} '
              f'({field_correct[field] / max(1, field_total[field]):.1%})')
    print(f'account-link sample comparison: matches_expected={account_correct}, '
          f'extra_vs_expected={account_incorrect}, abstained_expected={account_abstained}')
    if WRITE_MISMATCH_REPORT:
        write_mismatch_report(
            mismatch_cases, len(samples), status_correct, exact_rows,
            exact_semantic_sequences, exact_step_arrays, tp, fp, fn,
            evidence_correct, evidence_total, field_correct, field_total,
        )
        print(f'per-case mismatch report: {MISMATCH_REPORT}')


def write_mismatch_report(cases, count, status_correct, exact_rows,
                          exact_semantic_sequences, exact_step_arrays,
                          tp, fp, fn, evidence_correct, evidence_total,
                          field_correct, field_total):
    lines = [
        '# Sample Mismatch Report',
        '',
        'Generated by `python code\\\\main.py --eval --mismatch-report` from the '
        'current source and `dataset/sample_output.csv`.',
        '',
        '## Summary',
        '',
        f'- Cases: {count}',
        f'- Status accuracy: {status_correct}/{count} '
        f'({status_correct / max(1, count):.1%})',
        f'- Exact output rows: {exact_rows}/{count} '
        f'({exact_rows / max(1, count):.1%})',
        f'- Exact semantic step sequences: {exact_semantic_sequences}/{count}',
        f'- Exact full step arrays: {exact_step_arrays}/{count}',
        f'- Semantic step counts: {tp} TP, {fp} FP, {fn} FN',
        f'- Evidence ID accuracy: {evidence_correct}/{evidence_total}',
        '',
        '| Field (position-aligned) | Correct | Compared | Accuracy |',
        '|---|---:|---:|---:|',
    ]
    for field, correct in field_correct.items():
        total = field_total[field]
        lines.append(f'| `{field}` | {correct} | {total} | {correct / max(1, total):.1%} |')
    lines.extend(['', '## Case-level differences', ''])
    if not cases:
        lines.append('No differences against the supplied sample baseline.')
    for case in cases:
        lines.extend([
            f"### {case['case_id']}",
            '',
            f"- Status: expected `{case['expected_status']}`, "
            f"predicted `{case['predicted_status']}`.",
        ])
        if case['missing']:
            lines.append('- Missing semantic steps:')
            lines.extend(f'  - `{step}`' for step in case['missing'])
        if case['extra']:
            lines.append('- Extra semantic steps:')
            lines.extend(f'  - `{step}`' for step in case['extra'])
        if case['evidence_mismatches']:
            lines.append('- Evidence ID mismatches on matched semantic steps:')
            lines.extend(
                f'  - `{step}`: expected `{expected}`, predicted `{predicted}`'
                for step, expected, predicted in case['evidence_mismatches']
            )
        if case['expected_steps'] != case['predicted_steps']:
            lines.extend([
                '- Expected step array:',
                f'  ```json\n  {json.dumps(case["expected_steps"], separators=(",", ":"))}\n  ```',
                '- Predicted step array:',
                f'  ```json\n  {json.dumps(case["predicted_steps"], separators=(",", ":"))}\n  ```',
            ])
        lines.append('')
    MISMATCH_REPORT.parent.mkdir(parents=True, exist_ok=True)
    MISMATCH_REPORT.write_text('\n'.join(lines).rstrip() + '\n', encoding='utf-8')


if __name__ == '__main__':
    evaluate() if '--eval' in sys.argv else run()
