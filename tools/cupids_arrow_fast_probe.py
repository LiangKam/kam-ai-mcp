#!/usr/bin/env python3
from __future__ import annotations
import concurrent.futures as cf
import csv, hashlib, json, os, re, time, urllib.parse
from pathlib import Path
import requests

OUT=Path(os.environ.get('FAST_OUT','fast-probe-output')); RAW=OUT/'raw'; MEDIA=OUT/'media'
for p in (OUT,RAW,MEDIA): p.mkdir(parents=True,exist_ok=True)
DOMAIN='drcupidarrow.com'
UA='UnityPlayer/2022.3.62f3 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)'

def safe(s): return re.sub(r'[^A-Za-z0-9._-]+','_',s).strip('._')[:180] or 'item'
def kind(b,ct=''):
    if b.startswith(b'\x89PNG\r\n\x1a\n'): return 'png'
    if b.startswith(b'\xff\xd8\xff'): return 'jpg'
    if b[:4]==b'RIFF' and b[8:12]==b'WEBP': return 'webp'
    if len(b)>12 and b[4:8]==b'ftyp': return 'mp4'
    if b'#EXTM3U' in b[:4096]: return 'm3u8'
    if b.startswith(b'UnityFS'): return 'unityfs'
    s=b.lstrip()[:200].lower()
    if s.startswith((b'<html',b'<!doctype',b'<?xml')) or 'html' in ct.lower(): return 'html/xml'
    if s.startswith((b'{',b'[')) or 'json' in ct.lower(): return 'json'
    try: b[:4096].decode('utf-8'); return 'text'
    except: return 'binary'

def probe(item):
    label,url=item; started=time.time(); rrec={'label':label,'url':url}
    try:
        r=requests.get(url,headers={'User-Agent':UA,'Accept':'*/*','X-Unity-Version':'2022.3.62f3'},timeout=(5,12),allow_redirects=True,verify=True)
        b=r.content[:120_000_000]; ct=r.headers.get('content-type',''); k=kind(b,ct); sh=hashlib.sha256(b).hexdigest() if b else ''
        ext={'png':'.png','jpg':'.jpg','webp':'.webp','mp4':'.mp4','m3u8':'.m3u8','json':'.json','text':'.txt','html/xml':'.txt','unityfs':'.bundle'}.get(k,'.bin')
        d=MEDIA if k in {'png','jpg','webp','mp4','m3u8'} else RAW
        path=''
        if b:
            fp=d/f'{safe(label)}__{sh[:12]}{ext}'; fp.write_bytes(b); path=str(fp)
        rrec.update(status=r.status_code,ok=200<=r.status_code<400,final_url=r.url,content_type=ct,bytes=len(b),detected_type=k,sha256=sh,saved_path=path,headers=dict(r.headers),preview=b[:800].decode('utf-8','replace') if k in {'text','json','html/xml','m3u8'} else '')
    except Exception as e:
        rrec.update(status=None,ok=False,final_url=url,content_type='',bytes=0,detected_type='error',sha256='',saved_path='',error=f'{type(e).__name__}: {e}')
    rrec['elapsed_ms']=int((time.time()-started)*1000)
    print(json.dumps({x:rrec.get(x) for x in ('label','status','bytes','detected_type','error')},ensure_ascii=False),flush=True)
    return rrec

urls=[]
def add(label,url): urls.append((label,url))
# Base and bootstrap candidates
for scheme in ('https','http'):
    host=f'{scheme}://{DOMAIN}'
    for p in ('/','/privacy-policy.html','/robots.txt','/sitemap.xml','/dao_as/android/version_1_0_8','/dao_as/android/version_1_0_8/','/dao_as/android/version_1_0_8.txt','/dao_as/android/version_1_0_8/data_config.txt','/dao_as/android/version_1_0_8/version-android.txt','/dao_as/android/version_1_0_8/config.json'):
        add('base_'+safe(scheme+p),host+p)
# Plausible version roots
roots=[]
for patch in range(1,16):
    roots += [f'https://{DOMAIN}/dao_as/android/v_1_0_{patch}_AS/',f'https://{DOMAIN}/dao_as/android/v_1_0_{patch}/',f'https://{DOMAIN}/dao_as/android/version_1_0_{patch}/']
for root in [f'https://{DOMAIN}/dao_as/android/v_1_1_0_AS/',f'https://{DOMAIN}/dao_as/android/v_1_1_0/',f'https://{DOMAIN}/dao_as/android/version_1_1_0/']:
    roots.append(root)
manifest_names=('data_config.txt','data_config.json','version-android.txt','version.txt','manifest.json','config.json','res_config.txt','resource_config.txt')
for ri,root in enumerate(roots):
    for n in manifest_names: add(f'manifest_{ri:02d}_{n}',urllib.parse.urljoin(root,n))
# Known identifiers and bounded path templates
ids=['1010001','1010002','1010003','1010004','1010005','1010006','1010010','2050101','2050102','2050103','2050104','2051901','2051902','2051903','2051904']
primary_roots=[f'https://{DOMAIN}/dao_as/android/v_1_0_{p}_AS/' for p in range(1,16)]+[f'https://{DOMAIN}/dao_as/android/v_1_1_0_AS/']
templates=[
 '{id}.png','{id}.jpg','{id}.webp','{id}.mp4','{id}.m3u8','{id}.download','{id}',
 'image/{id}.png','images/{id}.png','img/{id}.png','res/{id}.png','media/{id}.png',
 'video/{id}.mp4','videos/{id}.mp4','media/{id}.mp4','video/{id}.download','videos/{id}.download',
 '{id}/1.png','{id}/1.mp4','{id}/01.png','{id}/01.mp4'
]
# All templates for static root; key candidates on other versions
for root in primary_roots:
    root_tag=safe(urllib.parse.urlparse(root).path)
    chosen=ids if root.endswith('/v_1_0_1_AS/') else ['1010004','2050101','2051901']
    for rid in chosen:
        for tpl in templates:
            rel=tpl.format(id=rid)
            add(f'media_{root_tag}_{rid}_{safe(rel)}',urllib.parse.urljoin(root,rel))
# Deduplicate
seen=set(); unique=[]
for i in urls:
    if i[1] not in seen: seen.add(i[1]); unique.append(i)
urls=unique
print(f'probing {len(urls)} unique URLs',flush=True)
with cf.ThreadPoolExecutor(max_workers=40) as ex:
    results=list(ex.map(probe,urls))
results.sort(key=lambda x:x['label'])
(OUT/'results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
fields=['label','status','ok','url','final_url','content_type','bytes','detected_type','sha256','saved_path','elapsed_ms','error','preview']
with (OUT/'results.csv').open('w',encoding='utf-8-sig',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader(); w.writerows(results)
valid=[r for r in results if r.get('detected_type') in {'png','jpg','webp','mp4','m3u8'}]
interesting=[r for r in results if r.get('status') not in (None,404) or r.get('detected_type') not in {'html/xml','error'}]
(OUT/'valid_media.json').write_text(json.dumps(valid,ensure_ascii=False,indent=2),encoding='utf-8')
(OUT/'interesting_results.json').write_text(json.dumps(interesting,ensure_ascii=False,indent=2),encoding='utf-8')
(OUT/'SUMMARY.md').write_text('\n'.join(['# Fast probe',f'- URLs: {len(results)}',f'- HTTP non-404/error: {sum(1 for r in results if r.get("status") not in (None,404))}',f'- Valid media: {len(valid)}',f'- Interesting: {len(interesting)}']),encoding='utf-8')
