#!/usr/bin/env python3
"""Convert a saved public Triage report to reviewable text and IOC contexts."""
from __future__ import annotations
import argparse, hashlib, html, json, re
from html.parser import HTMLParser
from pathlib import Path
class Text(HTMLParser):
    def __init__(self):super().__init__();self.parts=[];self.skip=0
    def handle_starttag(self,t,a):
        if t in ('script','style'):self.skip+=1
        elif t in ('p','li','div','tr','td','th','h1','h2','h3','br'):self.parts.append('\n')
    def handle_endtag(self,t):
        if t in ('script','style') and self.skip:self.skip-=1
        elif t in ('p','li','div','tr','td','th','h1','h2','h3'):self.parts.append('\n')
    def handle_data(self,d):
        if not self.skip:self.parts.append(d)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--html',required=True,type=Path);ap.add_argument('--output-dir',required=True,type=Path);a=ap.parse_args()
    raw=a.html.read_text(encoding='utf-8',errors='replace');p=Text();p.feed(raw);txt=html.unescape(''.join(p.parts));lines=[]
    for line in txt.splitlines():
        line=' '.join(line.split())
        if line:lines.append(line)
    text='\n'.join(lines);a.output_dir.mkdir(parents=True,exist_ok=True);(a.output_dir/'triage-text.txt').write_text(text,encoding='utf-8')
    endpoint=re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}')
    url=re.compile(r'https?://[^\s"\'<>]+',re.I)
    paths=re.compile(r'[A-Za-z]:\\[^\r\n"<>]{1,300}\.(?:exe|dll|js|vbs|hta|ps1|bat|cmd)',re.I)
    contexts=[]
    for m in endpoint.finditer(text):contexts.append({'endpoint':m.group(),'context':text[max(0,m.start()-350):m.end()+350]})
    result={'source_html_sha256':hashlib.sha256(raw.encode()).hexdigest(),'endpoints':sorted(set(endpoint.findall(text))),'urls':sorted(set(url.findall(text)))[:1000],'process_paths':sorted(set(paths.findall(text)))[:1000],'endpoint_contexts':contexts[:500],'executed_locally':False}
    (a.output_dir/'triage-evidence.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps({'endpoints':result['endpoints'],'paths':len(result['process_paths'])}))
if __name__=='__main__':main()
