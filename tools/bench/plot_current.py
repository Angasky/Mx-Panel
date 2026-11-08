"""Plot measured production-handler comparisons; no synthetic timing values."""
import argparse
import csv
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import font_manager
import numpy as np
from report import aggregate, ORDER, LABELS

p=argparse.ArgumentParser()
p.add_argument('results',type=Path)
p.add_argument('--font',type=Path,required=True)
a=p.parse_args()
font_manager.fontManager.addfont(str(a.font))
plt.rcParams.update({'font.family':font_manager.FontProperties(fname=str(a.font)).get_name(),'font.size':11,'axes.unicode_minus':False,'savefig.facecolor':'#f4f7fb','figure.facecolor':'#f4f7fb'})
source=json.loads(a.results.read_text())
r=aggregate(source)
out=a.results.parent
(out/'summary.json').write_text(json.dumps(r,ensure_ascii=False,indent=2))
with (out/'metrics.csv').open('w',newline='') as f:
 writer=csv.DictWriter(f,fieldnames=list(r['rows'][0]));writer.writeheader();writer.writerows(r['rows'])
colors={'Python':'#e6a23c','Go':'#2475c7'}
def row(runtime,n,c,key):return next(x for x in r['rows'] if (x['runtime'],x['nodes'],x['concurrency'],x['case'])==(runtime,n,c,key))
def style(ax):
 ax.set_facecolor('white');ax.spines[['top','right','left']].set_visible(False);ax.grid(axis='x',alpha=.2);ax.set_axisbelow(True);ax.tick_params(axis='y',length=0)
def heading(fig,title,subtitle):
 fig.suptitle(title,x=.05,y=.98,ha='left',fontsize=23,fontweight='bold',color='#172c45')
 fig.text(.05,.91,subtitle,fontsize=11,color='#536273')
def bars(ax,n,c,metric,keys):
 y=np.arange(len(keys));style(ax)
 for j,runtime in enumerate(['Python','Go']):
  vals=[row(runtime,n,c,key)[metric] for key in keys]
  ax.barh(y+(j-.5)*.32,vals,height=.29,color=colors[runtime],label=runtime,zorder=3)
  for yi,v in zip(y+(j-.5)*.32,vals):ax.text(v,yi,f'  {v:.2f}',va='center',fontsize=10)
 ax.set_yticks(y,[LABELS[k] for k in keys]);ax.invert_yaxis()
 maximum=max(row(rt,n,c,k)[metric] for rt in colors for k in keys)
 ax.set_xlim(0,maximum*1.24);ax.legend(loc='upper right',frameon=False)
 ax.set_title(f'{n:,} 节点 · 并发 {c}',loc='left',fontweight='bold',pad=16)
 ax.set_xlabel('平均响应耗时（毫秒，越低越好）' if metric=='meanMs' else 'P95 响应耗时（毫秒，越低越好）')
fig,axes=plt.subplots(1,2,figsize=(17,9))
heading(fig,'Python / Go 当前功能速度对比','8 项共有后台操作 ｜ 同机真实 HTTP 请求 ｜ 100 / 1,000 节点 ｜ 三轮交替运行')
for ax,n in zip(axes,[100,1000]):bars(ax,n,1,'meanMs',ORDER)
fig.subplots_adjust(left=.15,right=.96,top=.85,bottom=.21,wspace=.55)
fig.text(.05,.12,f"实测 {r['requests']:,} 次请求，失败 {r['errors']} 次；每场景预热 5 次。每轮读取 100 次、写入 30 次。",fontsize=11)
fig.text(.05,.078,'保存节点、流量设置和 YAML 均实际修改；内容未变的保存单列。使用 30 份订阅记录和相同节点数据。',fontsize=10,color='#536273')
fig.text(.05,.04,'仅比较当前实现：Go 与 Python 的校验、备份及 fsync 策略不同；不代表语言本身速度，也不含公网、SSH 或代理转发。',fontsize=10,color='#536273')
fig.savefig(out/'功能平均耗时.png',dpi=180);plt.close(fig)
fig,axes=plt.subplots(1,2,figsize=(17,8))
heading(fig,'4 并发读取 · 延迟与处理能力','每个请求建立新回环连接、读取完整响应；客户端结果校验不计入耗时')
for ax,n in zip(axes,[100,1000]):bars(ax,n,4,'p95Ms',ORDER[:4])
fig.subplots_adjust(left=.15,right=.96,top=.84,bottom=.27,wspace=.55)
lines=[]
for n in [100,1000]:
 parts=[f"{LABELS[k]} {row('Python',n,4,k)['rps']:.0f}/{row('Go',n,4,k)['rps']:.0f}" for k in ORDER[:4]]
 lines.append(f'{n:,} 节点吞吐（Python / Go，请求/秒）：'+ '；'.join(parts))
fig.text(.05,.16,lines[0],fontsize=10);fig.text(.05,.115,lines[1],fontsize=10)
fig.text(.05,.055,'P95：95% 的成功请求耗时不超过此值。吞吐包含本机客户端和连接开销，并非独立服务器极限。',fontsize=10,color='#536273')
fig.savefig(out/'并发读取对比.png',dpi=180);plt.close(fig)
fig,ax=plt.subplots(figsize=(17,9));ax.axis('off')
heading(fig,'1,000 节点 · 完整性能明细','单并发 ｜ P95 越低越好 ｜ 采样 RSS 为各场景前后观测值，不是精确峰值')
values=[]
for key in ORDER:
 py,go=row('Python',1000,1,key),row('Go',1000,1,key)
 ratio=py['meanMs']/go['meanMs'];winner=f'Go {ratio:.2f} 倍' if ratio>=1 else f'Python {1/ratio:.2f} 倍'
 values.append([LABELS[key],f"{py['meanMs']:.2f}",f"{go['meanMs']:.2f}",winner,f"{py['p95Ms']:.2f} / {go['p95Ms']:.2f}",f"{py['sampledRssMiB']:.1f} / {go['sampledRssMiB']:.1f}"])
table=ax.table(cellText=values,colLabels=['功能','Python 平均 ms','Go 平均 ms','平均耗时较快者','P95 ms（Py / Go）','RSS MiB（Py / Go）'],cellLoc='center',colWidths=[.22,.14,.12,.15,.19,.18],bbox=[0,.12,1,.78])
table.auto_set_font_size(False);table.set_fontsize(11)
for (i,j),cell in table.get_celld().items():
 cell.set_edgecolor('#dde5ed')
 cell.set_facecolor('#e7eef7' if i==0 else '#ffffff' if i%2 else '#f4f7fb')
 if i==0:cell.set_text_props(weight='bold',color='#172c45')
fig.subplots_adjust(left=.04,right=.96,top=.87,bottom=.12)
go_version=next(x['runtimeVersion'] for x in r['rows'] if x['runtime']=='Go')
fig.text(.05,.08,f"环境：Linux · Python {r['environment']['python']} · {go_version} · PyYAML {r['environment']['pyyaml']} / {r['environment']['yamlLoader']}",fontsize=10)
fig.text(.05,.035,'倍率 = 较慢实现平均耗时 / 较快实现平均耗时。数据源：同目录 results.json；当前本地 Go 源码，Python 原仓库 0869964。',fontsize=10,color='#536273')
fig.savefig(out/'性能明细.png',dpi=180);plt.close(fig)
print(json.dumps({'requests':r['requests'],'errors':r['errors'],'rows1000':values},ensure_ascii=False,indent=2))
