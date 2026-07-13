#!/usr/bin/env python3
"""Extract normalized AgentTesla or Remcos configuration fields from Triage text."""
from __future__ import annotations
import argparse,json,re
from pathlib import Path
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--text',required=True,type=Path);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args();lines=[x.strip()for x in a.text.read_text(encoding='utf-8',errors='replace').splitlines()if x.strip()]
    low=[x.lower()for x in lines];family='agenttesla' if 'agenttesla' in low else ('remcos' if 'remcos' in low else 'unknown');configs=[]
    if family=='agenttesla':
        for i,x in enumerate(low):
            if x!='protocol' or i+1>=len(lines):continue
            c={'protocol':lines[i+1]}
            for key in ('Host','Port','Username','Password'):
                try:j=lines.index(key,i+1,min(len(lines),i+40));c[key.lower()]=lines[j+1] if j+1<len(lines) else None
                except ValueError:pass
            if c not in configs:configs.append(c)
    elif family=='remcos':
        version=None
        for i,x in enumerate(low):
            if x=='version' and i+1<len(lines) and re.match(r'\d+\.\d+',lines[i+1]):version=lines[i+1];break
        c2=[]
        for i,x in enumerate(lines):
            if x=='C2':
                for v in lines[i+1:i+20]:
                    if v in ('Attributes','audio_folder','remcos.exe','copy_folder','Signatures'):break
                    if re.fullmatch(r'(?:[A-Za-z0-9.-]+|(?:\d{1,3}\.){3}\d{1,3}):\d{1,5}',v) and v not in c2:c2.append(v)
        if version or c2:configs=[{'version':version,'c2':c2}]
    result={'family':family,'configs':configs,'source':str(a.text),'executed_locally':False};a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':main()
