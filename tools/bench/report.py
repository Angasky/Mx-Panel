"""Render actual benchmark samples as portable HTML and an optional Canvas."""
import argparse
import hashlib
import json
import math
import statistics
from pathlib import Path

LABELS={'profiles':'订阅列表','snapshot':'节点列表快照','raw':'读取 YAML','subscription':'下载完整订阅','traffic-save':'保存流量设置','node-save':'保存节点（真实修改）','node-noop':'保存节点（内容未变）','raw-save':'保存完整 YAML'}
ORDER=list(LABELS)

def aggregate(result):
    groups={}
    for run in result['runs']:groups.setdefault((run['runtime'],run['nodes'],run['case'],run['concurrency']),[]).append(run)
    rows=[]
    for (runtime,nodes,case,concurrency),runs in groups.items():
        samples=[s for r in runs for s in r['samples']];values=sorted(s['ms'] for s in samples if s['ok'])
        position=(len(values)-1)*.95;lo=math.floor(position);hi=math.ceil(position)
        wall=sum(r['wallSeconds'] for r in runs)
        rows.append({'runtime':runtime,'nodes':nodes,'case':case,'label':LABELS[case],'concurrency':concurrency,'requests':len(samples),'errors':sum(not s['ok'] for s in samples),'meanMs':statistics.mean(values),'p50Ms':statistics.median(values),'p95Ms':values[lo]+(values[hi]-values[lo])*(position-lo),'rps':len(values)/wall,'cpuMsPerRequest':sum(r['cpuMs'] for r in runs)/len(samples),'sampledRssMiB':max(r['sampledRssMiB'] for r in runs),'rounds':len(runs),'responseBytes':statistics.mean(r['responseBytes'] for r in runs),'runtimeVersion':runs[0]['runtimeVersion']})
    return {'sourceRevision':result['sourceRevision'],'timeUTC':result['timeUTC'],'environment':result['environment'],'methodology':result['methodology'],'requests':sum(r['requests'] for r in rows),'errors':sum(r['errors'] for r in rows),'rows':rows}

HTML=r'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Python / Go 后台性能实测</title>
<style>:root{color-scheme:light dark;--bg:#fafafa;--fg:#17202a;--muted:#5b6470;--line:#d9dee3;--surface:#fff;--go:#2563eb;--py:#64748b}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.65 system-ui,sans-serif}main{max-width:1100px;margin:32px auto;padding:0 24px}h1{font-size:24px;margin:0 0 8px}h2{font-size:19px;margin:30px 0 10px}p{margin:6px 0}.muted{color:var(--muted);font-size:13px}.controls{display:flex;gap:18px;flex-wrap:wrap;margin:22px 0}label{display:grid;gap:5px}select{padding:9px 13px;background:var(--surface);color:var(--fg);border:1px solid var(--line);border-radius:6px;font:inherit}.note{padding:16px;border-left:3px solid var(--go);background:var(--surface);margin:18px 0}.legend{display:flex;flex-wrap:wrap;gap:20px;font-size:13px}.legend i{display:inline-block;width:12px;height:12px;background:var(--py);margin-right:6px}.legend .go{background:var(--go)}.chart{margin:18px 0}.bar-row{display:grid;grid-template-columns:190px 1fr;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)}.bar-pair{display:grid;gap:5px}.bar-item{display:flex;align-items:center;gap:9px}.bar{height:13px;background:var(--py);min-width:1px}.bar.go{background:var(--go)}.bar.baseline{background:var(--surface);border:1px solid var(--py)}.legend .baseline{background:var(--surface);border:1px solid var(--py)}.value{white-space:nowrap;font-size:12px}.scroll{overflow:auto}table{width:100%;border-collapse:collapse;white-space:nowrap;font-size:13px}th,td{text-align:right;padding:10px;border-bottom:1px solid var(--line)}th:first-child,td:first-child{text-align:left}footer{overflow-wrap:anywhere;margin-top:28px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}code{font-size:12px}a{color:var(--go)}@media(max-width:650px){main{padding:0 14px}.bar-row{grid-template-columns:1fr;gap:3px}.controls{gap:10px}}@media(prefers-color-scheme:dark){:root{--bg:#121416;--fg:#e3e7eb;--muted:#a3aab2;--line:#353b43;--surface:#1b1e23;--go:#7da5fb;--py:#8997ab}}</style>
<main><h1>Python / Go 后台性能实测</h1><p id="meta" class="muted"></p><p id="totals"></p>
<div class="note"><strong>当前实现各有快慢，不能按语言名称推断结果。</strong><p>__NOTE__</p></div>
<div class="controls"><label>节点规模<select id="size"><option value="1000">1,000 节点</option><option value="100">100 节点</option></select></label><label>并发请求<select id="concurrency"><option value="1">1（读取与写入）</option><option value="4">4（仅读取）</option></select></label><label>图表指标<select id="metric"><option value="meanMs">平均 HTTP 耗时 · ms</option><option value="p95Ms">P95 HTTP 耗时 · ms</option><option value="rps">成功请求吞吐 · 请求/秒</option></select></label></div>
<h2 id="chart-title"></h2><div class="legend" id="legend"></div><p id="axis" class="muted"></p><div class="chart" id="chart"></div><p class="muted">纵轴：后台操作场景。横轴：所选指标。每格汇总三轮全部样本；预热五次。HTTP 新建连接，读取完整响应后停止计时；客户端语义检查在计时之外。</p>
<h2>延迟、吞吐与资源明细</h2><div class="scroll"><table><thead><tr><th>操作 / 后端</th><th>平均 ms</th><th>P50 ms</th><th>P95 ms</th><th>请求/秒</th><th>CPU ms/请求</th><th>采样 RSS MiB</th><th>失败/请求</th></tr></thead><tbody id="rows"></tbody></table></div>
<h2>测试条件与边界</h2><ul><li>同一台机器，相同节点配置、30 份订阅记录；三轮交替运行顺序，读取并发 1 / 4，写入并发 1。</li><li>流量设置、节点修改及 YAML 保存每次更改实际字段；内容未变保存单列。</li><li>只启用生产 HTTP Handler；不启用定时更新、SSH、计量和外部网络访问，不包含 TLS 加密或代理转发速度。</li><li>真实备份与镜像文件保留。Go 的 fsync 成本与 Python 原子替换策略不同；写入结果不是严格同等持久化语义下的语言对比。</li><li>Go 仍在迁移，完整协议校验覆盖尚未对齐；这里测试的是相同有效数据经过当前共有接口的表现，不代表最终完整功能对等的结果。</li><li>RSS 为场景前后采样的最大值，不是精确峰值。Windows 文件系统与后台负载影响结果，不能直接外推线上 Linux。</li></ul><footer id="footer"></footer></main>
<script>const report=__DATA__;const labels=__LABELS__;const order=__ORDER__;
const displayRows=[...report.rows,...report.referenceRows];document.querySelector('#legend').innerHTML=report.runtimes.map(runtime=>'<span><i class="'+(runtime==='Go'?'go':runtime==='Go 优化前'?'baseline':'')+'"></i>'+runtime+'</span>').join('');
document.querySelector('#meta').textContent=report.environment.os+' · Python '+report.environment.python+' · '+report.rows.find(r=>r.runtime==='Go').runtimeVersion+' · '+report.environment.logicalCPUs+' 逻辑核 · '+report.environment.memoryGiB.toFixed(1)+' GiB 内存';
document.querySelector('#totals').textContent='实测 '+report.requests.toLocaleString()+' 次请求，失败 '+report.errors+' 次。数据源：独立本机 HTTP 测试，'+new Date(report.timeUTC).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai'})+'（北京时间）。'+(report.referenceRows.length?'另展示优化前 Go 的 '+report.referenceRequests.toLocaleString()+' 次参考请求；两轮独立执行。':'');
document.querySelector('#footer').textContent='源码提交 '+report.sourceRevision+'；PyYAML '+report.environment.pyyaml+' / '+report.environment.yamlLoader+'。原始样本见同目录 results.json。'+(report.referenceSource?'优化前基线提交 '+report.referenceSource+'；摘要校验值 '+report.referenceSha256:'');
function render(){const n=Number(document.querySelector('#size').value),c=Number(document.querySelector('#concurrency').value),m=document.querySelector('#metric').value,rows=displayRows.filter(r=>r.nodes===n&&r.concurrency===c),cases=order.filter(k=>rows.some(r=>r.case===k)),max=Math.max(...rows.map(r=>r[m])),unit=m==='rps'?'请求/秒':'ms';document.querySelector('#chart-title').textContent=n.toLocaleString()+' 节点 / 并发 '+c+'：'+(m==='rps'?'吞吐（越高越好）':m==='p95Ms'?'P95 耗时（越低越好）':'平均耗时（越低越好）');document.querySelector('#axis').textContent='横轴：'+unit+'，各场景采用共同尺度，最大值 '+max.toFixed(2)+' '+unit;document.querySelector('#chart').innerHTML=cases.map(k=>'<div class="bar-row"><span>'+labels[k]+'</span><div class="bar-pair">'+report.runtimes.map(runtime=>{const r=rows.find(r=>r.case===k&&r.runtime===runtime);return '<div class="bar-item"><span class="bar '+(runtime==='Go'?'go':runtime==='Go 优化前'?'baseline':'')+'" style="width:'+((r[m]/max)*82)+'%"></span><span class="value">'+r[m].toFixed(2)+' '+unit+'</span></div>'}).join('')+'</div></div>').join('');document.querySelector('#rows').innerHTML=cases.flatMap(k=>report.runtimes.map(runtime=>rows.find(r=>r.case===k&&r.runtime===runtime))).map(r=>'<tr><td>'+r.label+' / '+r.runtime+'</td>'+['meanMs','p50Ms','p95Ms','rps','cpuMsPerRequest','sampledRssMiB'].map(k=>'<td>'+r[k].toFixed(2)+'</td>').join('')+'<td>'+r.errors+'/'+r.requests+'</td></tr>').join('')};document.querySelectorAll('select').forEach(s=>s.onchange=render);render();</script></html>'''

CANVAS=r'''import { useState,useHostTheme,Stack,Row,H1,H2,Text,BarChart,Table } from "cursor/canvas";
const report=__DATA__;
const labels:Record<string,string>=__LABELS__;
const order=__ORDER__;
type Metric="meanMs"|"p95Ms"|"rps";
export default function PerformanceComparison(){
 const theme=useHostTheme();const[n,setN]=useState(1000);const[c,setC]=useState(1);const[m,setM]=useState<Metric>("meanMs");
 const rows=displayRows.filter(r=>r.nodes===n&&r.concurrency===c);const cases=order.filter(k=>rows.some(r=>r.case===k));
 const styles={background:theme.bg.elevated,color:theme.text.primary,border:"1px solid "+theme.stroke.primary,padding:"8px 12px",borderRadius:6};
 const fmt=(v:number)=>v.toFixed(2);const unit=m==="rps"?" 请求/秒":" ms";
 const tableRows=cases.flatMap(k=>report.runtimes.map(runtime=>rows.find(r=>r.case===k&&r.runtime===runtime)!)).map(r=>[r.label+" / "+r.runtime,fmt(r.meanMs),fmt(r.p50Ms),fmt(r.p95Ms),fmt(r.rps),fmt(r.cpuMsPerRequest),fmt(r.sampledRssMiB),r.errors+"/"+r.requests]);
 return <Stack gap={16} style={{padding:24,color:theme.text.primary}}>
  <H1>Python / Go 后台性能实测</H1>
  <Text>{report.requests.toLocaleString()} 次本轮场景请求，失败 {report.errors} 次；同机、同配置、三轮交替测试。另含 {report.referenceRequests} 次优化前 Go 参考请求（独立运行）。</Text>
  <Text tone="secondary">{report.environment.os} · Python {report.environment.python} · {report.rows.find(r=>r.runtime==="Go")!.runtimeVersion} · {report.environment.logicalCPUs} 逻辑核 / {report.environment.memoryGiB.toFixed(1)} GiB</Text>
  <div style={{padding:16,borderLeft:"3px solid "+theme.accent.primary,background:theme.fill.tertiary}}>__NOTE__</div>
  <Row gap={16} wrap>
   <label>节点规模 <select value={n} onChange={e=>setN(Number(e.target.value))} style={styles}><option value={1000}>1,000 节点</option><option value={100}>100 节点</option></select></label>
   <label>并发 <select value={c} onChange={e=>setC(Number(e.target.value))} style={styles}><option value={1}>1（读写）</option><option value={4}>4（仅读取）</option></select></label>
   <label>指标 <select value={m} onChange={e=>setM(e.target.value as Metric)} style={styles}><option value="meanMs">平均耗时</option><option value="p95Ms">P95 耗时</option><option value="rps">成功请求吞吐</option></select></label>
  </Row>
  <H2>{n.toLocaleString()} 节点 / 并发 {c}：{m==="rps"?"成功请求吞吐（越高越好）":m==="p95Ms"?"P95 HTTP 耗时（越低越好）":"平均 HTTP 耗时（越低越好）"}</H2>
  <Text size="small" tone="secondary">纵轴：后台操作场景；横轴：{m==="rps"?"请求/秒":"毫秒"}。图例：{report.runtimes.join(" / ")}。来源：本机生产 HTTP Handler，{new Date(report.timeUTC).toLocaleString("zh-CN",{timeZone:"Asia/Shanghai"})}（北京时间），三轮汇总；客户端语义验证在计时之外。</Text>
  <BarChart horizontal categories={cases.map(k=>labels[k])} series={report.runtimes.map(runtime=>({name:runtime,tone:runtime==="Go"?"info" as const:"neutral" as const,data:cases.map(k=>rows.find(r=>r.case===k&&r.runtime===runtime)![m])}))} height={Math.max(280,cases.length*(report.runtimes.length===3?90:65))} valueSuffix={unit} showValues/>
  <H2>延迟与资源明细</H2>
  <Table headers={["操作 / 后端","平均 ms","P50 ms","P95 ms","请求/秒","CPU ms/请求","采样 RSS MiB","失败/请求"]} rows={tableRows} columnAlign={["left","right","right","right","right","right","right","right"]}/>
  <H2>方法与边界</H2>
  <Text tone="secondary">30 份订阅记录，100 / 1,000 节点；每场景预热 5 次，读请求每轮 60 次，写请求每轮 12 次。真实修改与内容未变保存分开。结果覆盖完整响应和本地备份、镜像；不包含公网、SSH、TLS 加密、代理转发或后台计量。</Text>
  <Text tone="secondary">RSS 是场景前后采样最大值，不是精确峰值。Go 使用额外 fsync，Python 保留原默认原子替换策略；Go 完整协议校验尚未对齐，本结果不代表最终完整功能对等或 Linux 线上表现。源码：{report.sourceRevision}。</Text>
 </Stack>
}
'''

def main():
    p=argparse.ArgumentParser();p.add_argument('input',type=Path);p.add_argument('--output',type=Path,required=True);p.add_argument('--canvas',type=Path);p.add_argument('--baseline',type=Path);args=p.parse_args()
    raw=args.input.read_bytes();source=json.loads(raw);summary=aggregate(source)
    summary['rawSha256']=hashlib.sha256(raw).hexdigest()
    summary.update(runtimes=['Python','Go'],referenceRows=[],referenceRequests=0,referenceSource='',referenceSha256='')
    if args.baseline:
        baseline_raw=args.baseline.read_bytes();baseline=json.loads(baseline_raw)
        if baseline['environment']!=source['environment'] or baseline['methodology']!=source['methodology']:
            raise SystemExit('baseline environment or methodology changed; report separately')
        if {(r['nodes'],r['fixtureSha256']) for r in baseline['runs']}!={(r['nodes'],r['fixtureSha256']) for r in source['runs']}:
            raise SystemExit('baseline fixtures differ')
        reference=aggregate(baseline)
        summary['referenceRows']=[{**r,'runtime':'Go 优化前'} for r in reference['rows'] if r['runtime']=='Go']
        summary['referenceRequests']=sum(r['requests'] for r in summary['referenceRows'])
        summary['referenceSource']=baseline['sourceRevision'];summary['referenceSha256']=hashlib.sha256(baseline_raw).hexdigest()
        summary['runtimes']=['Python','Go 优化前','Go']
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/'results.json').write_bytes(raw)
    (args.output/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    note='Python 已有 YAML / 快照缓存与未变更跳过写入；本轮 Go 已加入有界内容缓存、快照 JSON 复用和未变更保存跳过，配置保存仍同步备份与镜像到磁盘。灰色参考线来自保留的优化前基线，分次运行会受机器负载影响。' if args.baseline else '测试保留所记录版本的缓存、备份、镜像和落盘策略；Go 的 fsync 与 Python 默认原子替换策略不同。具体实现以对应源码提交为准，差异不能全部归因于语言。'
    values={'__NOTE__':note,'__DATA__':json.dumps(summary,ensure_ascii=False).replace('<','\\u003c'),'__LABELS__':json.dumps(LABELS,ensure_ascii=False),'__ORDER__':json.dumps(ORDER)}
    def expand(text):
        for key,value in values.items():text=text.replace(key,value)
        return text
    (args.output/'report.html').write_text(expand(HTML),encoding='utf-8')
    if args.canvas:args.canvas.write_text(expand(CANVAS),encoding='utf-8')
    print('measured requests',summary['requests'],'failures',summary['errors'])
    for case in ORDER:
        values={r['runtime']:r for r in summary['rows'] if r['nodes']==1000 and r['concurrency']==1 and r['case']==case}
        print(case,'Python',round(values['Python']['meanMs'],2),'Go',round(values['Go']['meanMs'],2))
    print('REPORT',str((args.output/'report.html').resolve()))

if __name__=='__main__':main()
