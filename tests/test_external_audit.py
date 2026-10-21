"""External audit tests, no live phishing URL fetches."""
import csv,io,sys,zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from evaluate_external import normalize_or_none,filter_novel,read_urls

def test_normalization_and_overlap():
    sample=["https://login.example.co.uk/","https://shop.elsewhere.org","https://shop.elsewhere.org","javascript:alert(1)"]
    urls,meta=filter_novel(sample,{"example.co.uk"},50)
    assert urls==["https://shop.elsewhere.org/"]
    assert meta["overlap_with_uci_domains"]==1
    assert meta["duplicates"]==1
    assert meta["invalid"]==1

def test_tranco_is_not_ground_truth(tmp_path):
    archive=tmp_path/"tranco.zip"
    with zipfile.ZipFile(archive,"w") as f:f.writestr("top-1m.csv","1,example.com\n2,github.com\n")
    urls,sha=read_urls(archive,"popular",20)
    assert urls==["https://example.com/","https://github.com/"]
    assert len(sha)==64

def test_phishtank_verified_only(tmp_path):
    path=tmp_path/"online-valid.csv"
    path.write_text("url,verified,online\nhttps://a.example,yes,yes\nhttps://b.example,no,yes\nhttps://c.example,yes,no\n")
    urls,sha=read_urls(path,"phishing",10)
    assert urls==["https://a.example"]

def test_unsupported_url_never_scored():
    assert normalize_or_none("file:///etc/passwd") is None
