"""Frozen prospective positive-only PhishTank audit. Never visits URLs from input."""
import argparse,csv,gzip,hashlib,io,json,sys
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"src"))
from phishing_analyzer.model import load_model,predict
from phishing_analyzer.urls import normalize_url,domain_group
CUTOFF=datetime(2026,10,23,tzinfo=timezone.utc)

def date_utc(value):
    if not isinstance(value,str) or not value.strip():return None
    try:
        d=datetime.fromisoformat(value.strip().replace("Z","+00:00"))
        return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
    except ValueError:return None

def uci_groups(csv_path):
    with open(csv_path,encoding="utf-8-sig",newline="") as fh:
        rows=csv.DictReader(fh)
        field=next((n for n in rows.fieldnames or [] if n.lower()=="url"),None)
        if field is None:raise ValueError("UCI URL column missing")
        groups=set()
        for row in rows:
            try:groups.add(domain_group(normalize_url(row[field])))
            except (ValueError,TypeError):pass
    return groups

def select_phishing(path,excluded,min_count=200):
    if min_count<1:raise ValueError("min_count must be positive")
    raw=Path(path).read_bytes()
    if len(raw)>20_000_000:raise ValueError("Archive too large")
    with (gzip.GzipFile(fileobj=io.BytesIO(raw)) if raw[:2]==b"\x1f\x8b" else io.BytesIO(raw)) as fh:
        decoded=fh.read(100_000_001)
    if len(decoded)>100_000_000:raise ValueError("Expanded feed too large")
    reader=csv.DictReader(io.StringIO(decoded.decode("utf-8-sig")))
    required={"url","verified","online","submission_time","verification_time"}
    if not required.issubset(reader.fieldnames or []):raise ValueError("Timestamp and verification columns required")
    counts=Counter();seen=set();urls=[]
    for row in reader:
        counts["examined"]+=1
        if row["verified"].lower()!="yes" or row["online"].lower()!="yes":
            counts["not_verified_online"]+=1;continue
        submitted=date_utc(row.get("submission_time"));verified=date_utc(row.get("verification_time"))
        if submitted is None or verified is None:counts["missing_dates"]+=1;continue
        if submitted<CUTOFF or verified<CUTOFF:counts["predates_cutoff"]+=1;continue
        try:url=normalize_url(row["url"])
        except (ValueError,TypeError):counts["invalid_url"]+=1;continue
        if url in seen:counts["duplicates"]+=1;continue
        seen.add(url)
        if domain_group(url) in excluded:counts["overlap_with_uci"]+=1;continue
        urls.append(url)
    counts["retained"]=len(urls)
    if len(urls)<min_count:raise ValueError(f"Insufficient future samples: {len(urls)} < {min_count}; no metric published")
    return urls,dict(counts),hashlib.sha256(raw).hexdigest()

def main():
    p=argparse.ArgumentParser()
    for flag in ("uci-csv","phishing-csv"):p.add_argument("--"+flag,required=True)
    p.add_argument("--model-dir",default="frozen/models")
    p.add_argument("--min-count",type=int,default=200)
    p.add_argument("--out",default="reports/prospective_holdout.json")
    a=p.parse_args()
    if datetime.now(timezone.utc)<CUTOFF:p.error("Pre-registered future cutoff has not arrived")
    model,meta=load_model(a.model_dir)
    if model is None or meta.get("version")!="2.1.0":p.error("Frozen trusted v2.1 model missing")
    urls,selection,digest=select_phishing(a.phishing_csv,uci_groups(a.uci_csv),a.min_count)
    decisions=Counter(predict(url,model,meta)["label"] for url in urls)
    count=len(urls)
    report={"protocol":"preregistered-positive-holdout-v1","cutoff_utc":CUTOFF.isoformat(),
        "checked_at_utc":datetime.now(timezone.utc).isoformat(),
        "frozen_training_commit":"9a3ced00d98a40773837e0f52aa236c9c1b3c45f",
        "model_version":"2.1.0","feed_sha256":digest,"selection":selection,
        "positive_class_only":{"count":count,"decisions":{k:decisions[k] for k in ("PHISHING","UNCERTAIN","LEGITIMATE")},
         "detected_fraction":decisions["PHISHING"]/count,
         "false_clear_fraction":decisions["LEGITIMATE"]/count,
         "uncertain_fraction":decisions["UNCERTAIN"]/count},
        "limitations":["Not a negative-class benchmark; do not infer accuracy or false-positive rate.",
         "Do not select or tune models using this untouched holdout.", "No suspect URL was visited."]}
    dest=Path(a.out);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(report,indent=2)+"\n",encoding="utf8")
    print(json.dumps(report,indent=2))
if __name__=="__main__":main()
