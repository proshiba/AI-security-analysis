#!/usr/bin/env python3
"""Inventory an ISO9660 member inside a MalwareBazaar ZIP without mounting it."""
from __future__ import annotations
import argparse, hashlib, json, struct
from pathlib import Path
import pyzipper

SECTOR=2048
def sha(b):return hashlib.sha256(b).hexdigest()
def records(image,extent,size,prefix=''):
    data=image[extent*SECTOR:extent*SECTOR+size];out=[];pos=0
    while pos<len(data):
        length=data[pos]
        if length==0:pos=((pos//SECTOR)+1)*SECTOR;continue
        rec=data[pos:pos+length]
        if len(rec)<34:break
        lba=struct.unpack_from('<I',rec,2)[0];n=struct.unpack_from('<I',rec,10)[0];flags=rec[25];namelen=rec[32];name=rec[33:33+namelen].decode('latin1',errors='replace')
        pos+=length
        if name in ('\x00','\x01'):continue
        name=name.split(';')[0];path=f'{prefix}/{name}'.lstrip('/')
        item={'path':path,'extent_lba':lba,'size':n,'directory':bool(flags&2)}
        if item['directory']:item['children']=records(image,lba,n,path)
        else:
            blob=image[lba*SECTOR:lba*SECTOR+n];item.update({'sha256':sha(blob),'magic':blob[:16].hex(),'mz_offsets':[i for i in range(len(blob)) if blob.startswith(b'MZ',i)][:20]})
        out.append(item)
    return out
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--outer-zip',required=True,type=Path);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
    with pyzipper.AESZipFile(a.outer_zip)as z:z.setpassword(b'infected');i=next(x for x in z.infolist()if not x.is_dir());image=z.read(i)
    pvd=image[16*SECTOR:17*SECTOR]
    if pvd[1:6]!=b'CD001':raise RuntimeError('not ISO9660')
    root=pvd[156:156+pvd[156]];extent=struct.unpack_from('<I',root,2)[0];size=struct.unpack_from('<I',root,10)[0]
    result={'member':i.filename,'sha256':sha(image),'volume_identifier':pvd[40:72].decode('ascii',errors='replace').strip(),'files':records(image,extent,size),'executed':False,'mounted':False}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps({'volume':result['volume_identifier'],'entries':len(result['files'])}))
if __name__=='__main__':main()
