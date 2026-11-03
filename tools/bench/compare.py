"""Reproducible loopback HTTP comparison; never opens production data or URLs."""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import math
import os
import platform
import queue
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path

import psutil
import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
import server as reference

PASSWORD = 'isolated-performance-password'
SLUG = 'a'*48

def fixtures(root, count, auth):
    root.mkdir()
    nodes = [{'name':f'Node-{i:04d}','type':'trojan','server':'edge.example.invalid','port':20001+i,'password':'fixture-password','tls':True,'sni':'edge.example.invalid'} for i in range(count)]
    doc = {'proxies':nodes,'proxy-groups':[{'name':'Proxy','type':'select','proxies':['DIRECT']+[n['name'] for n in nodes]}], 'rules':['MATCH,Proxy']}
    text = reference.yaml_dump(doc)
    for name in ('primary.yaml','mirror.yaml'):(root/name).write_text(text,encoding='utf-8',newline='\n')
    (root/'auth.json').write_text(json.dumps(auth),encoding='utf-8')
    profiles=[{'id':'clash','name':'Benchmark','slug':SLUG,'protected':True,'files':[str(root/'primary.yaml'),str(root/'mirror.yaml')]}]
    for i in range(1,30):
        path=root/f'profile-{i}.yaml';path.write_text(text,encoding='utf-8',newline='\n')
        profiles.append({'id':f'p{i}','name':f'Fixture-{i}','slug':hashlib.sha256(str(i).encode()).hexdigest()[:48],'files':[str(path)]})
    (root/'profiles.json').write_text(json.dumps({'profiles':profiles}),encoding='utf-8')
    return doc,text

def percentile(values, q):
    v=sorted(values);at=(len(v)-1)*q;lo=math.floor(at);hi=math.ceil(at)
    return v[lo]+(v[hi]-v[lo])*(at-lo)

def request(port,method,path,body=None,cookie=''):
    headers={'Origin':f'https://127.0.0.1:{port}','X-Forwarded-Proto':'https','X-Profile':'clash','Connection':'close'}
    if body is not None:headers['Content-Type']='application/json';body=json.dumps(body,ensure_ascii=False).encode()
    if cookie:headers['Cookie']='mxioc_session='+cookie
    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=30)
    start=time.perf_counter()
    try:
        connection.request(method,path,body=body,headers=headers);response=connection.getresponse();data=response.read()
        elapsed=(time.perf_counter()-start)*1000
        return elapsed,response.status,data,response.getheaders()
    finally:connection.close()

def validate(case,data,count):
    if case=='subscription':return len(reference.yaml_load(data)['proxies'])==count
    obj=json.loads(data)
    if 'error' in obj:return False
    if case=='snapshot':return len(obj['nodes'])==count
    if case=='profiles':return len(obj['profiles'])==30
    if case=='raw':return 'proxies:' in obj.get('yaml','')
    return True

def run_process(runtime,root,binary):
    log=(root/'stderr.log').open('w',encoding='utf-8')
    args=[sys.executable,'-X','utf8',str(REPO/'tools/bench/python_server.py'),str(root)] if runtime=='Python' else [str(binary),'-root',str(root)]
    process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=log,text=True,encoding='utf-8',cwd=REPO)
    lines=queue.Queue()
    threading.Thread(target=lambda:lines.put(process.stdout.readline()),daemon=True).start()
    try:ready=json.loads(lines.get(timeout=20));port=ready['port']
    except Exception:
        process.terminate();process.wait(timeout=5);log.close();raise RuntimeError('benchmark server startup failed: '+(root/'stderr.log').read_text(encoding='utf-8'))
    return process,log,port,ready.get('runtimeVersion',sys.version.split()[0])

def run_one(runtime,root,binary,count,round_index,auth,args):
    doc,text=fixtures(root,count,auth)
    process,log,port,version=run_process(runtime,root,binary)
    try:
        _,status,data,headers=request(port,'POST','/admin/api/login',{'username':'benchmark','password':PASSWORD})
        if status!=200:raise RuntimeError(f'{runtime} login failed: '+data.decode()[:100])
        cookie=SimpleCookie();cookie.load(next(v for k,v in headers if k.lower()=='set-cookie'));token=cookie['mxioc_session'].value
        proc=psutil.Process(process.pid)
        cases=[('profiles','GET','/admin/api/profiles',None),('snapshot','GET','/admin/api/snapshot',None),('raw','GET','/admin/api/raw',None),('subscription','GET','/sub/'+SLUG,None),
               ('traffic-save','PUT','/admin/api/traffic',{'upload':12345,'download':67890,'enforce':False}),
               ('node-save','PUT','/admin/api/nodes',{'oldName':'Node-0000','config':doc['proxies'][0]}),
               ('node-noop','PUT','/admin/api/nodes',{'oldName':'Node-0000','config':doc['proxies'][0]}),
               ('raw-save','PUT','/admin/api/raw',{'yaml':text})]
        metrics=[]
        for case,method,path,body in cases:
            concurrencies=[1,4] if method=='GET' else [1]
            for concurrency in concurrencies:
                def request_body(tag):
                    if case=='node-save':return {**body,'config':{**body['config'],'password':'benchmark-'+tag}}
                    if case=='traffic-save':return {**body,'upload':12345+int(tag.split('-')[-1])+(100 if tag.startswith('request') else 0)}
                    if case=='raw-save':return {'yaml':text+'benchmark-sequence: '+tag+'\n'}
                    return body
                for warmup in range(5):
                    _,status,payload,_=request(port,method,path,request_body('warmup-'+str(warmup)),token)
                    if status!=200 or not validate(case,payload,count):raise RuntimeError(f'{runtime} {case} warmup invalid: {status} '+payload.decode(errors='replace')[:100])
                cpu=proc.cpu_times();rss_before=proc.memory_info().rss
                number=args.requests if method=='GET' else args.write_requests
                start=time.perf_counter()
                def one(i):
                    try:
                        elapsed,status,payload,_=request(port,method,path,request_body('request-'+str(i)),token)
                        return {'ms':elapsed,'ok':status==200,'bytes':len(payload),'status':status,'payload':payload}
                    except Exception as e:return {'ms':None,'ok':False,'error':type(e).__name__}
                with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:samples=list(pool.map(one,range(number)))
                wall=time.perf_counter()-start;after=proc.cpu_times();rss_after=proc.memory_info().rss
                for sample in samples:
                    payload=sample.pop('payload',None)
                    if sample['ok']:
                        try:sample['ok']=validate(case,payload,count)
                        except Exception:sample['ok']=False
                latencies=[s['ms'] for s in samples if s['ok']]
                if not latencies:raise RuntimeError(f'{runtime} {case} all requests failed')
                row={'runtime':runtime,'nodes':count,'round':round_index,'case':case,'concurrency':concurrency,'requests':number,'errors':sum(not s['ok'] for s in samples),'meanMs':statistics.mean(latencies),'p50Ms':statistics.median(latencies),'p95Ms':percentile(latencies,.95),'wallSeconds':wall,'successfulRps':len(latencies)/wall,'cpuMs':((after.user+after.system)-(cpu.user+cpu.system))*1000,'sampledRssMiB':max(rss_before,rss_after)/1048576,'responseBytes':statistics.mean(s['bytes'] for s in samples if s['ok']),'samples':samples}
                row['runtimeVersion']=version
                row['fixtureSha256']=hashlib.sha256(text.encode()).hexdigest()
                metrics.append(row)
                print(f"{runtime} nodes={count} round={round_index} {case} c={concurrency} mean={row['meanMs']:.2f}ms errors={row['errors']}",flush=True)
        _,status,data,_=request(port,'GET','/admin/api/snapshot',cookie=token)
        if status!=200 or not validate('snapshot',data,count):raise RuntimeError('final state integrity failed')
        mirror=(root/'mirror.yaml').read_bytes();primary=(root/'primary.yaml').read_bytes()
        if mirror!=primary:raise RuntimeError('mirrored write integrity failed')
        return metrics
    finally:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        log.close()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--go-bin',type=Path,required=True);parser.add_argument('--nodes',default='100,1000');parser.add_argument('--rounds',type=int,default=3);parser.add_argument('--requests',type=int,default=60);parser.add_argument('--write-requests',type=int,default=12);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();binary=args.go_bin.resolve()
    salt,digest=reference.password_hash(PASSWORD,iterations=600000);auth={'username':'benchmark','salt':salt,'hash':digest,'iterations':600000}
    result={'timeUTC':datetime.now(timezone.utc).isoformat(),'sourceRevision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),'environment':{'os':platform.platform(),'cpu':platform.processor(),'logicalCPUs':psutil.cpu_count(),'physicalCPUs':psutil.cpu_count(logical=False),'memoryGiB':psutil.virtual_memory().total/1073741824,'python':sys.version.split()[0],'pyyaml':yaml.__version__,'yamlLoader':reference.YamlLoader.__name__},'methodology':{'profiles':30,'warmupPerCase':5,'rounds':args.rounds,'connection':'new loopback HTTP connection per request; trusted HTTPS forwarding header; no TLS encryption','backgroundWorkers':False,'externalNetwork':False,'backupsAndMirrors':True,'readConcurrency':[1,4],'writeConcurrency':[1],'throughputIncludesClientValidation':False,'latencyExcludesClientValidation':True,'scope':'Production HTTP handlers; local data and storage. Not proxy throughput or SSH latency.'},'runs':[]}
    with tempfile.TemporaryDirectory(prefix='mxioc-performance-') as temporary:
        for count in map(int,args.nodes.split(',')):
            for round_index in range(args.rounds):
                order=['Python','Go'] if round_index%2==0 else ['Go','Python']
                for runtime in order:
                    root=Path(temporary)/f'{runtime}-{count}-{round_index}'
                    result['runs'].extend(run_one(runtime,root,binary,count,round_index,auth,args))
                    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    if any(row['errors'] for row in result['runs']):raise SystemExit('benchmark completed with failed requests; inspect raw results')
    print('RESULT '+str(args.output.resolve()),flush=True)

if __name__=='__main__':main()
