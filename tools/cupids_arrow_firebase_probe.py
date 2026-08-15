#!/usr/bin/env python3
"""Fetch the app's public client-side Firebase Remote Config using the same
Firebase Installations + Remote Config protocol as the Android SDK.

The API key/app id/package/certificate below are public client identifiers
embedded in the publicly distributed APK. No admin API or privileged token is used.
"""
from __future__ import annotations
import base64, concurrent.futures as cf, csv, gzip, hashlib, json, os, random, re, secrets, time, urllib.parse
from pathlib import Path
from typing import Any
import requests

OUT=Path(os.environ.get('FRC_OUT','firebase-probe-output')); RAW=OUT/'raw'; MEDIA=OUT/'media'
for p in (OUT,RAW,MEDIA): p.mkdir(parents=True,exist_ok=True)
API_KEY='AIzaSyDxVstIOH4nEb7cRN9Iiyfj6keqoBwz3FA'
PROJECT_ID='dao-arrow'; PROJECT_NUMBER='441964133579'
APP_ID='1:441964133579:android:648bb1faf2fd76a11bef4e'
PACKAGE='com.cupidarrow.arrowout.puzzle.gp'
CERT='911172D56E68C31A37444BD543F6E7EF8CE76A66'
FIS_URL=f'https://firebaseinstallations.googleapis.com/v1/projects/{PROJECT_ID}/installations'
FRC_URL=f'https://firebaseremoteconfig.googleapis.com/v1/projects/{PROJECT_NUMBER}/namespaces/firebase:fetch'
SESSION=requests.Session()

def write_json(p,obj): p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(obj,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
def fid():
    b=bytearray(secrets.token_bytes(17)); b[0]=(b[0]&0x0f)|0x70
    return base64.urlsafe_b64encode(bytes(b)).decode().rstrip('=')[:22]
def safe(s): return re.sub(r'[^A-Za-z0-9._-]+','_',str(s)).strip('._')[:180] or 'item'
def dtype(b,ct=''):
    if b.startswith(b'\x89PNG\r\n\x1a\n'): return 'png'
    if b.startswith(b'\xff\xd8\xff'): return 'jpg'
    if b[:4]==b'RIFF' and b[8:12]==b'WEBP': return 'webp'
    if len(b)>12 and b[4:8]==b'ftyp': return 'mp4'
    if b'#EXTM3U' in b[:4096]: return 'm3u8'
    if b.startswith(b'UnityFS'): return 'unityfs'
    s=b.lstrip()[:300].lower()
    if s.startswith((b'{',b'[')) or 'json' in ct.lower(): return 'json'
    if s.startswith((b'<html',b'<!doctype',b'<?xml')) or 'html' in ct.lower(): return 'html/xml'
    try: b[:4096].decode('utf-8'); return 'text'
    except: return 'binary'
def create_installation(tag):
    f=fid(); body={'fid':f,'appId':APP_ID,'authVersion':'FIS_v2','sdkVersion':'a:17.2.0'}
    headers={'Content-Type':'application/json','Accept':'application/json','Content-Encoding':'gzip','Cache-Control':'no-cache','x-goog-api-key':API_KEY,'X-Android-Package':PACKAGE,'X-Android-Cert':CERT}
    raw=json.dumps(body,separators=(',',':')).encode(); r=SESSION.post(FIS_URL,headers=headers,data=gzip.compress(raw),timeout=30)
    rec={'tag':tag,'request_url':FIS_URL,'request_body':body,'status':r.status_code,'headers':dict(r.headers),'response_text':r.text}
    try: rec['response']=r.json()
    except: rec['response']=None
    write_json(RAW/f'fis_{safe(tag)}.json',rec)
    if r.status_code not in (200,201) or not isinstance(rec['response'],dict): return rec,None,None
    rr=rec['response']; token=(rr.get('authToken') or {}).get('token'); returned_fid=rr.get('fid') or f
    return rec,returned_fid,token

def fetch_rc(tag,install_fid,token,profile):
    body={
      'appInstanceId':install_fid,'appInstanceIdToken':token,'appId':APP_ID,
      'countryCode':profile['country'],'languageCode':profile['language'],
      'platformVersion':profile.get('platform','33'),'timeZone':profile.get('timezone','UTC'),
      'appVersion':profile.get('app_version','1.1.0'),'appBuild':profile.get('app_build','10'),
      'packageName':PACKAGE,'sdkVersion':profile.get('sdk_version','21.6.1'),
      'analyticsUserProperties':profile.get('analytics',{}),
      'firstOpenTime':profile.get('first_open','2026-08-15T00:00:00.000Z')
    }
    if profile.get('custom_signals'): body['customSignals']=profile['custom_signals']
    headers={'X-Goog-Api-Key':API_KEY,'X-Android-Package':PACKAGE,'X-Android-Cert':CERT,'X-Google-GFE-Can-Retry':'yes','X-Goog-Firebase-Installations-Auth':token,'Content-Type':'application/json','Accept':'application/json','User-Agent':'Dalvik/2.1.0 (Linux; U; Android 13; Pixel 7 Build/TQ3A.230805.001)'}
    r=SESSION.post(FRC_URL,headers=headers,json=body,timeout=40)
    rec={'tag':tag,'profile':profile,'request_url':FRC_URL,'request_body':body,'status':r.status_code,'headers':dict(r.headers),'response_text':r.text}
    try: rec['response']=r.json()
    except: rec['response']=None
    write_json(RAW/f'frc_{safe(tag)}.json',rec)
    return rec

def walk_strings(x,path='$'):
    out=[]
    if isinstance(x,dict):
      for k,v in x.items(): out += walk_strings(v,path+'.'+str(k))
    elif isinstance(x,list):
      for i,v in enumerate(x): out += walk_strings(v,f'{path}[{i}]')
    elif isinstance(x,str):
      out.append((path,x))
      s=x.strip()
      if s[:1] in '[{':
        try: out += walk_strings(json.loads(s),path+'<json>')
        except: pass
      # try one level of base64 JSON
      if len(s)>20 and re.fullmatch(r'[A-Za-z0-9_+/=-]+',s):
        try:
          b=base64.b64decode(s+'='*((4-len(s)%4)%4)); t=b.decode('utf-8')
          if t.lstrip()[:1] in '[{': out += walk_strings(json.loads(t),path+'<b64json>')
        except: pass
    return out

def download(url,label):
    rec={'url':url,'label':label}
    try:
      r=SESSION.get(url,headers={'User-Agent':'UnityPlayer/2022.3.62f3 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)','Accept':'*/*','X-Unity-Version':'2022.3.62f3'},timeout=(8,35),allow_redirects=True)
      b=r.content[:150_000_000]; k=dtype(b,r.headers.get('content-type','')); sh=hashlib.sha256(b).hexdigest() if b else ''
      ext={'png':'.png','jpg':'.jpg','webp':'.webp','mp4':'.mp4','m3u8':'.m3u8','json':'.json','text':'.txt','html/xml':'.txt','unityfs':'.bundle'}.get(k,'.bin')
      d=MEDIA if k in {'png','jpg','webp','mp4','m3u8'} else RAW; path=''
      if b:
        p=d/f'{safe(label)}__{sh[:12]}{ext}'; p.write_bytes(b); path=str(p)
      rec.update(status=r.status_code,final_url=r.url,headers=dict(r.headers),bytes=len(b),detected_type=k,sha256=sh,saved_path=path,preview=b[:1200].decode('utf-8','replace') if k in {'json','text','html/xml','m3u8'} else '')
    except Exception as e: rec.update(status=None,bytes=0,detected_type='error',error=f'{type(e).__name__}: {e}')
    print(json.dumps({k:rec.get(k) for k in ('label','status','bytes','detected_type','error')},ensure_ascii=False),flush=True)
    return rec

profiles=[
 {'name':'US_en','country':'US','language':'en-US','timezone':'America/Los_Angeles'},
 {'name':'JP_ja','country':'JP','language':'ja-JP','timezone':'Asia/Tokyo'},
 {'name':'IN_en','country':'IN','language':'en-IN','timezone':'Asia/Kolkata'},
 {'name':'PK_en','country':'PK','language':'en-PK','timezone':'Asia/Karachi'},
 {'name':'GB_en','country':'GB','language':'en-GB','timezone':'Europe/London'},
 {'name':'DE_de','country':'DE','language':'de-DE','timezone':'Europe/Berlin'},
 {'name':'BR_pt','country':'BR','language':'pt-BR','timezone':'America/Sao_Paulo'},
 {'name':'CN_zh','country':'CN','language':'zh-CN','timezone':'Asia/Shanghai'},
 {'name':'US_review','country':'US','language':'en-US','timezone':'America/Los_Angeles','analytics':{'user_attribution':'review','UserAB':'USpecial1','nf_platform':'gp'}},
 {'name':'US_organic','country':'US','language':'en-US','timezone':'America/Los_Angeles','analytics':{'user_attribution':'organic','ad_platform':'organic','nf_platform':'gp'}},
 {'name':'US_old_108','country':'US','language':'en-US','timezone':'America/Los_Angeles','app_version':'1.0.8','app_build':'8'},
 {'name':'US_old_104','country':'US','language':'en-US','timezone':'America/Los_Angeles','app_version':'1.0.4','app_build':'4'},
]
results=[]
# Each profile gets a real, ordinary client installation so country and experiment evaluation are independent.
for i,p in enumerate(profiles):
    tag=f'{i:02d}_{p["name"]}'
    fis,fi,tok=create_installation(tag); results.append({'type':'fis',**fis})
    print('FIS',tag,fis.get('status'),fi,flush=True)
    if fi and tok:
      rc=fetch_rc(tag,fi,tok,p); results.append({'type':'frc',**rc}); print('FRC',tag,rc.get('status'),flush=True)
    time.sleep(0.2)
write_json(OUT/'all_requests.json',results)
# Flatten every returned string, URL and likely resource/server/config field.
strings=[]; urls=set(); interesting=[]
for rec in results:
    if rec.get('type')!='frc' or not isinstance(rec.get('response'),dict): continue
    for path,val in walk_strings(rec['response']):
      strings.append({'tag':rec['tag'],'path':path,'value':val})
      for u in re.findall(r'https?://[^\s\"\'<>\\]+',val): urls.add(u.rstrip(')]},;'))
      low=(path+' '+val).lower()
      if any(w in low for w in ('resource','commonurl','server','download','video','image','review','special','userab','dao_as','version_')):
        interesting.append({'tag':rec['tag'],'path':path,'value':val})
write_json(OUT/'flattened_strings.json',strings); write_json(OUT/'interesting_values.json',interesting); write_json(OUT/'discovered_urls.json',sorted(urls))
with (OUT/'interesting_values.csv').open('w',encoding='utf-8-sig',newline='') as f:
    w=csv.DictWriter(f,fieldnames=['tag','path','value']); w.writeheader(); w.writerows(interesting)
# Build direct candidates from discovered first-party roots and any explicit URL.
fetch_urls=set(urls)
roots=[]
for row in strings:
    v=row['value'].strip()
    if v.startswith('http') and ('drcupidarrow.com' in v or 'dao_as' in v):
      roots.append(v if v.endswith('/') else v+'/')
for root in roots:
    fetch_urls.update({urllib.parse.urljoin(root,'data_config.txt'),urllib.parse.urljoin(root,'version-android.txt'),urllib.parse.urljoin(root,'1010004.png'),urllib.parse.urljoin(root,'1010004.download'),urllib.parse.urljoin(root,'2050101.png'),urllib.parse.urljoin(root,'2050101.mp4'),urllib.parse.urljoin(root,'2050101.download')})
with cf.ThreadPoolExecutor(max_workers=16) as ex:
    downloads=list(ex.map(lambda x:download(x[1],f'url_{x[0]:04d}'),enumerate(sorted(fetch_urls)[:1000])))
write_json(OUT/'download_results.json',downloads)
valid=[d for d in downloads if d.get('detected_type') in {'png','jpg','webp','mp4','m3u8'}]
write_json(OUT/'valid_media.json',valid)
(OUT/'SUMMARY.md').write_text('\n'.join(['# Firebase client probe',f'- FIS/Remote Config records: {len(results)}',f'- Flattened strings: {len(strings)}',f'- Interesting values: {len(interesting)}',f'- URLs: {len(urls)}',f'- Download attempts: {len(downloads)}',f'- Valid media: {len(valid)}']),encoding='utf-8')
