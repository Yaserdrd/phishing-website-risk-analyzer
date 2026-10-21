"""Independent-source URL-only audit. Never visits input URLs."""
import argparse,csv,hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from phishing_analyzer.model import load_model,predict
from phishing_analyzer.urls import normalize_url,domain_group

def read_urls(path,kind,limit):
    import gzip,io,zipfile
    raw=Path(path).read_bytes()
    if kind=="phishing":
        txt=gzip.decompress(raw) if raw[:2]==b"\x1f\x8b" else raw
        reader=csv.DictReader(io.StringIO(txt.decode("utf-8-sig")))
        if not {"url","verified","online"}.issubset(reader.fieldnames or []):
            raise ValueError("Expected PhishTank verified, online, url fields")
        urls=[row["url"] for row in reader if row["verified"].lower()=="yes" and row["online"].lower()=="yes"]
    else:
        with zipfile.ZipFile(path) as z:
            files=[f for f in z.infolist() if f.filename.endswith(".csv") and not f.is_dir()]
            if len(files)!=1 or files[0].file_size>35_000_000: raise ValueError("Unexpected Tranco ZIP")
            with z.open(files[0]) as f:
                urls=["https://"+r[1]+"/" for r in csv.reader(io.TextIOWrapper(f,encoding="utf8")) if len(r)>1]
    return urls[:limit*5],hashlib.sha256(raw).hexdigest()

def normalize_or_none(url):
    try: return normalize_url(url)
    except (ValueError,TypeError): return None

def original_domains(path):
    with open(path,newline="",encoding="utf-8-sig") as f:
        reader=csv.DictReader(f)
        key=next((c for c in reader.fieldnames or [] if c.lower()=="url"),None)
        if key is None: raise ValueError("UCI file requires a URL column")
        return {domain_group(u) for row in reader if (u:=normalize_or_none(row[key]))}

def filter_novel(urls,blocked,limit):
    counts={"seen":len(urls),"invalid":0,"duplicates":0,"overlap_with_uci_domains":0}
    seen=set();out=[]
    for item in urls:
        u=normalize_or_none(item)
        if u is None: counts["invalid"]+=1;continue
        if u in seen: counts["duplicates"]+=1;continue
        seen.add(u)
        if domain_group(u) in blocked: counts["overlap_with_uci_domains"]+=1;continue
        out.append(u)
        if len(out)==limit:break
    counts["retained"]=len(out)
    return out,counts

def score(urls,model,meta):
    counts={k:0 for k in ("PHISHING","UNCERTAIN","LEGITIMATE")}
    for url in urls: counts[predict(url,model,meta)["label"]]+=1
    return {"count":len(urls),"decisions":counts,"fraction":{k:v/len(urls) for k,v in counts.items()}}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--model-dir",default="models")
    parser.add_argument("--uci-csv",required=True)
    parser.add_argument("--phishing-csv",required=True,help="PhishTank online-valid.csv(.gz)")
    parser.add_argument("--popular-zip",required=True,help="Tranco top-1m.csv.zip")
    parser.add_argument("--sample",type=int,default=2000)
    parser.add_argument("--out",default="reports/external_audit.json")
    args=parser.parse_args()
    if not 1<=args.sample<=10000: parser.error("sample must be 1..10000")
    model,meta=load_model(args.model_dir)
    if model is None: parser.error("No trusted trained model found")
    blocked=original_domains(args.uci_csv)
    rawp,hashp=read_urls(args.phishing_csv,"phishing",args.sample)
    rawt,hasht=read_urls(args.popular_zip,"popular",args.sample)
    ph,pc=filter_novel(rawp,blocked,args.sample)
    pop,tc=filter_novel(rawt,blocked,args.sample)
    if not ph or not pop: parser.error("Novel-domain samples are empty")
    result={"model_version":meta["version"],"source_fingerprints":{"phishtank_sha256":hashp,"tranco_sha256":hasht},
        "selection":{"phishing":pc,"popular":tc},"phishing_verified_online":score(ph,model,meta),
        "popular_domains_unverified":score(pop,model,meta),
        "limitations":["Tranco popularity does NOT establish benign ground truth.","Not a combined accuracy test.","Only URL strings were scored; no suspected URL was visited.","Overlap excludes every UCI domain, including its test partition.","Provider feeds can change; snapshot hashes recorded."]}
    dest=Path(args.out);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(result,indent=2)+"\n",encoding="utf8")
    print(json.dumps(result,indent=2))
if __name__=="__main__":main()
