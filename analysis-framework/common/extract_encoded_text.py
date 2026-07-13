#!/usr/bin/env python3
"""Extract textual Base64/charcode layers without executing them."""
from __future__ import annotations
import argparse, base64, hashlib, json, re
from pathlib import Path
import pyzipper

B64=re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")
URL=re.compile(r"https?://[^\s\"'<>]+",re.I)
DOMAIN=re.compile(r"(?<![\w.-])(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}(?::\d{1,5})?",re.I)
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def text(blob:bytes):
    if len(blob)>3 and blob[1::2].count(0)>len(blob)//6:return blob.decode('utf-16le',errors='replace'),'utf-16le'
    if len(blob)>3 and blob[0::2].count(0)>len(blob)//6:return blob.decode('utf-16be',errors='replace'),'utf-16be'
    for enc in ('utf-8-sig','utf-16','latin1'):
        try:return blob.decode(enc),enc
        except Exception:pass
    return blob.decode('latin1',errors='replace'),'latin1'
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--outer-zip',required=True,type=Path);ap.add_argument('--output-dir',required=True,type=Path);a=ap.parse_args()
    with pyzipper.AESZipFile(a.outer_zip) as z:
        z.setpassword(b'infected'); info=next(x for x in z.infolist() if not x.is_dir()); raw=z.read(info)
    source,_=text(raw);out=[];a.output_dir.mkdir(parents=True,exist_ok=True)
    seen=set()
    for i,m in enumerate(B64.finditer(source)):
        try:blob=base64.b64decode(m.group()+('='*(-len(m.group())%4)),validate=False)
        except Exception:continue
        if len(blob)<16 or sha(blob) in seen:continue
        seen.add(sha(blob));decoded,enc=text(blob);ratio=sum(c.isprintable() or c in '\r\n\t' for c in decoded)/max(1,len(decoded))
        item={'index':i,'encoded_offset':m.start(),'decoded_size':len(blob),'decoded_sha256':sha(blob),'magic':blob[:16].hex(),'encoding':enc,'printable_ratio':round(ratio,3),'urls':sorted(set(URL.findall(decoded))),'domains':sorted({x.lower() for x in DOMAIN.findall(decoded)})}
        if ratio>.75:
            name=f'layer-{i:03d}-{sha(blob)[:12]}.txt';(a.output_dir/name).write_text(decoded,encoding='utf-8',errors='replace');item['text_file']=name
        out.append(item)
    result={'member':info.filename,'sha256':sha(raw),'layers':out,'executed':False,'network_contacted':False}
    (a.output_dir/'encoded-text.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'member':info.filename,'layers':len(out),'text_layers':sum('text_file'in x for x in out),'urls':sorted({u for x in out for u in x['urls']})},ensure_ascii=False))
if __name__=='__main__':main()
