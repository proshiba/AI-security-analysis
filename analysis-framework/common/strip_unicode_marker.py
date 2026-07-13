#!/usr/bin/env python3
"""Strip repeated high-Unicode junk markers and rebuild concatenated script strings."""
from __future__ import annotations
import argparse, collections, hashlib, json, re
from pathlib import Path
import pyzipper

QUOTED=re.compile(r'(["\'])(.*?)(?<!\\)\1',re.S)
APPEND=re.compile(r'(?m)(?:this\.)?([A-Za-z_$][\w$]*)\s*\+=\s*(["\'])(.*?)(?<!\\)\2\s*;',re.S)
URL=re.compile(r'https?://[^\s"\'<>]+',re.I)
def sha(b:bytes):return hashlib.sha256(b).hexdigest()
def decode(b:bytes):
    for e in ('utf-8-sig','utf-16','utf-16le','latin1'):
        try:return b.decode(e)
        except Exception:pass
    return b.decode('latin1',errors='replace')
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--outer-zip',required=True,type=Path);ap.add_argument('--output-dir',required=True,type=Path);a=ap.parse_args()
    with pyzipper.AESZipFile(a.outer_zip) as z:z.setpassword(b'infected');i=next(x for x in z.infolist()if not x.is_dir());raw=z.read(i)
    src=decode(raw); strings=[m.group(2) for m in QUOTED.finditer(src)]
    candidates=[s for s in strings if 8<=len(s)<=80 and sum(ord(c)>127 for c in s)/len(s)>.6]
    marker,count=(collections.Counter(candidates).most_common(1)[0] if candidates else ('',0))
    clean=src.replace(marker,'') if marker else src
    groups=collections.defaultdict(list)
    for m in APPEND.finditer(clean):groups[m.group(1)].append(m.group(3))
    rebuilt={name:''.join(parts) for name,parts in groups.items()}
    a.output_dir.mkdir(parents=True,exist_ok=True); artifacts=[]
    for name,value in sorted(rebuilt.items(),key=lambda x:len(x[1]),reverse=True):
        if len(value)<40:continue
        safe=re.sub(r'[^A-Za-z0-9_.-]','_',name)[:60];path=a.output_dir/f'{safe}.rebuilt.txt';path.write_text(value,encoding='utf-8',errors='replace')
        artifacts.append({'variable':name,'length':len(value),'sha256':sha(value.encode(errors='replace')),'file':path.name,'urls':sorted(set(URL.findall(value))),'preview':value[:500]})
    result={'member':i.filename,'sha256':sha(raw),'marker':marker,'marker_occurrences':src.count(marker) if marker else 0,'rebuilt':artifacts[:100],'executed':False,'network_contacted':False}
    (a.output_dir/'unicode-marker.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'member':i.filename,'marker_length':len(marker),'marker_occurrences':result['marker_occurrences'],'rebuilt':[(x['variable'],x['length'],x['urls'])for x in artifacts[:5]]},ensure_ascii=False))
if __name__=='__main__':main()
