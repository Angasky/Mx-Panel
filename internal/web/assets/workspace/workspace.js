/* Local workspace interactions. No analytics, remote dependencies or credentials in storage. */
(() => {
 'use strict';
 const byId=id=>document.getElementById(id);
 const focusable=root=>[...root.querySelectorAll('button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),summary')].filter(e=>e.getClientRects().length);
 const sectionNames={overview:'工作台',profiles:'订阅与用户',servers:'服务器与监控',nodes:'节点与路由',settings:'系统设置',assistant:'AI 工作区'};
 let dialogQueue=Promise.resolve(),serial=0,pendingFrame=0,replay=false;
 function dialog({title,body,accept='确认操作',input=false,initial='',danger=false,inform=false}){
  const context={page:S.page,profile:S.profile,modal:S.modalEpoch,role:S.role};
  const valid=()=>context.page===S.page&&context.profile===S.profile&&context.modal===S.modalEpoch&&context.role===S.role;
  const task=()=>new Promise(resolve=>{
   if(!valid()){resolve(input?null:false);return}
   const previous=document.activeElement;
   const box=document.createElement('dialog');box.className='ws-dialog';const id='ws-dialog-'+(++serial);
   box.setAttribute('aria-labelledby',id);box.innerHTML=`<div class="ws-dialog-head"><h3 id="${id}">${esc(title)}</h3></div><div class="ws-dialog-body"></div><div class="ws-dialog-foot"><button class="btn" data-cancel>取消</button><button class="btn ${danger?'danger':'primary'}" data-accept>${esc(accept)}</button></div>`;
   const area=box.querySelector('.ws-dialog-body');area.textContent=body;
   let field;if(input){const label=document.createElement('label');label.htmlFor=id+'-value';label.textContent=body;field=document.createElement('input');field.id=label.htmlFor;field.value=initial;field.maxLength=/复制/.test(body)?20000:253;area.textContent='';area.append(label,field)}
   const finish=value=>{const unchanged=valid();box.close();box.remove();if(previous?.isConnected)previous.focus({preventScroll:true});resolve(unchanged?value:input?null:false)};
   if(inform)box.querySelector('[data-cancel]').hidden=true;
   box.querySelector('[data-cancel]').onclick=()=>finish(input?null:false);box.querySelector('[data-accept]').onclick=()=>finish(input?field.value:true);
   box.addEventListener('cancel',e=>{e.preventDefault();finish(input?null:false)});box.addEventListener('keydown',e=>{if(e.key==='Enter'&&input&&e.target===field){e.preventDefault();finish(field.value)}});
   document.body.append(box);box.showModal();(field||box.querySelector(inform?'[data-accept]':'[data-cancel]')).focus();if(field)field.select();
  });
  const result=dialogQueue.then(task);dialogQueue=result.catch(()=>{});return result;
 }
 window.showMessage=message=>{void dialog({title:'操作信息',body:String(message),accept:'关闭',inform:true})};
 window.confirmAction=message=>dialog({title:'确认操作',body:String(message),danger:/删除|撤销|清空|卸载|重置|移除|回滚/.test(message)});
 window.promptAction=(message,initial='')=>dialog({title:/复制/.test(message)?'复制链接':'输入信息',body:String(message),input:true,initial,accept:/复制/.test(message)?'完成':'确认'});
 function search(mode='all'){
  if(!S.role||S.role==='user')return;
  setNavigationOpen(false,false);const previous=document.activeElement;
  const box=document.createElement('dialog');box.className='ws-dialog';box.setAttribute('aria-label',mode==='profiles'?'切换订阅':'搜索功能与订阅');
  box.innerHTML='<div class="ws-command-search"><label for="wsCommandInput">'+(mode==='profiles'?'切换当前订阅':'搜索功能与订阅')+'</label><input id="wsCommandInput" autocomplete="off" placeholder="输入名称，使用方向键选择"></div><div class="ws-command-list"></div><div class="ws-dialog-foot"><span class="hint">↑ ↓ 选择 · Enter 打开 · Esc 返回</span><button class="btn" data-close>关闭</button></div>';
  const close=()=>{box.close();box.remove();if(previous?.isConnected)previous.focus({preventScroll:true})};box.querySelector('[data-close]').onclick=close;box.addEventListener('cancel',e=>{e.preventDefault();close()});
  const rows=[];if(mode!=='profiles')for(const [page,info] of Object.entries(pageInfo))rows.push({name:info[0],detail:sectionNames[sectionFor(page)],run:()=>go(page)});
  for(const p of S.profiles)rows.push({name:p.name,detail:p.id===S.profile?'当前订阅':'订阅',run:()=>useProfile(encodeURIComponent(p.id),['profiles','servers','monitoring','probeSync','settings','system','maintenance'].includes(S.page)?'overview':S.page)});
  const input=box.querySelector('input'),list=box.querySelector('.ws-command-list');
  const draw=()=>{const q=input.value.toLocaleLowerCase().trim();const matches=rows.filter(x=>(x.name+' '+x.detail).toLocaleLowerCase().includes(q));list.replaceChildren();for(const row of matches){const b=document.createElement('button');b.type='button';b.className='ws-command-item';b.innerHTML=`<span>${esc(row.name)}</span><small>${esc(row.detail)}</small>`;b.onclick=()=>{close();Promise.resolve(row.run()).catch(e=>notice(e.message))};list.append(b)}if(!matches.length){const p=document.createElement('p');p.className='empty';p.textContent='没有匹配结果，请换一个关键词。';list.append(p)}};
  input.oninput=draw;box.addEventListener('keydown',e=>{const items=[...list.querySelectorAll('button')],at=items.indexOf(document.activeElement);if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();items[(at+(e.key==='ArrowDown'?1:-1)+items.length)%items.length]?.focus()}if(e.key==='Enter'&&e.target===input){e.preventDefault();items[0]?.click()}});
  document.body.append(box);box.showModal();draw();input.focus();
 }
 function prepareEditor(){
  const area=byId('modalBody');if(!area)return;
  for(const form of area.querySelectorAll('form')){
   if(form.dataset.wsPrepared)continue;form.dataset.wsPrepared='true';
   if(form.id==='serverForm'){
    const grid=form.querySelector(':scope > .grid');
    if(grid){const sections=[['服务器身份',['rsName','rsHost','rsNodeAddress']],['SSH 连接与验证',['rsPort','rsUser','rsPassword','rsTrust']],['面板与内核',['rsInstallType','rsCoreConfig','rsMode','rsDomain','rsPanelAddress','rsPanelUser','rsPanelPassword']]];
     for(const [title,ids] of sections){const section=document.createElement('fieldset');section.className='ws-form-section';const legend=document.createElement('legend');legend.textContent=title;const fields=document.createElement('div');fields.className='grid';section.append(legend,fields);for(const id of ids){const control=byId(id);let node=control;while(node&&node.parentElement!==grid)node=node.parentElement;if(node)fields.append(node)}grid.before(section)}if(!grid.children.length)grid.remove();
    }
   }
   const submits=[...form.querySelectorAll('button[type=submit],button:not([type])')].filter(b=>!b.closest('.toolbar')&&!b.closest('details'));
   if(submits.length===1){const footer=document.createElement('div');footer.className='ws-form-actions';submits[0].before(footer);footer.append(submits[0]);const cancel=document.createElement('button');cancel.type='button';cancel.className='btn';cancel.textContent='返回页面';cancel.onclick=closeModal;footer.prepend(cancel)}
  }
  const heads=[...area.querySelectorAll('h4')].filter(h=>!h.closest('details'));
  if(heads.length>2&&!area.querySelector('.ws-form-index')){const nav=document.createElement('nav');nav.className='ws-form-index';nav.setAttribute('aria-label','编辑内容目录');for(const h of heads){h.classList.add('ws-section-heading');if(!h.id)h.id='ws-section-'+(++serial);const b=document.createElement('button');b.type='button';b.className='btn small';b.textContent=h.textContent;b.onclick=()=>h.scrollIntoView({block:'start',behavior:'auto'});nav.append(b)}area.prepend(nav)}
 }
 function prepare(root){
  if(!root)return;
  // Pair existing controls with visible labels without replacing event-bound nodes.
  for(const label of root.querySelectorAll('label')){
   if(label.htmlFor||label.querySelector('input,select,textarea')||label.dataset.wsLabel)continue;
   const next=label.nextElementSibling;if(next?.matches('input,select,textarea')){if(!next.id)next.id='ws-field-'+(++serial);label.htmlFor=next.id;label.dataset.wsLabel='true'}
  }
  for(const field of root.querySelectorAll('input:not([type=checkbox]):not([type=radio]):not([type=hidden]),select,textarea')){
   if(field.dataset.wsNamed)continue;field.dataset.wsNamed='true';
   if(field.labels?.length||field.closest('label'))continue;
   const name=field.getAttribute('aria-label');if(!name)continue;
   // Filters get a visible caption; generated URLs already have their card title.
   if(field.classList.contains('subscription-url')||field.readOnly)continue;
   if(!field.id)field.id='ws-field-'+(++serial);
   const wrap=document.createElement('div');wrap.className='ws-filter-field';const label=document.createElement('label');label.htmlFor=field.id;label.textContent=name;field.before(wrap);wrap.append(label,field);
  }
  for(const table of root.querySelectorAll('table')){if(table.parentElement.classList.contains('table-wrap'))continue;const wrap=document.createElement('div');wrap.className='table-wrap';wrap.tabIndex=0;wrap.setAttribute('role','region');wrap.setAttribute('aria-label',table.getAttribute('aria-label')||'数据表格，可横向滚动');table.before(wrap);wrap.append(table)}
  for(const error of root.querySelectorAll('.error')){if(!error.hasAttribute('role'))error.setAttribute('role','alert')}
  if(root===byId('modalBody'))prepareEditor();
 }
 function preparePage(){
  const root=byId('content');if(!root)return;prepare(root);prepare(byId('modalBody'));
  if(root.dataset.wsPage!==S.page){root.dataset.wsPage=S.page;let pref='cards';try{pref=localStorage.getItem('mx-view-'+S.page)||'cards'}catch{}root.dataset.view=pref}
  if(['servers','profiles','nodes'].includes(S.page)&&root.querySelector('.profile-grid,.node-grid')&&!root.querySelector('.ws-view-control')){
   const host=root.querySelector('.panel-head');if(host){const toggle=document.createElement('button');toggle.type='button';toggle.className='btn small ws-view-control';toggle.textContent=root.dataset.view==='list'?'切换卡片':'切换列表';toggle.setAttribute('aria-label','切换列表或卡片布局');toggle.onclick=()=>{root.dataset.view=root.dataset.view==='list'?'cards':'list';toggle.textContent=root.dataset.view==='list'?'切换卡片':'切换列表';try{localStorage.setItem('mx-view-'+S.page,root.dataset.view)}catch{}};host.append(toggle)}
  }
  const breadcrumbs=document.querySelector('.workspace-context');if(breadcrumbs&&S.role!=='user'){const section=sectionNames[sectionFor(S.page)]||'工作区',title=pageInfo[S.page]?.[0]||'';const text=section===title?title:section+' / '+title;if(breadcrumbs.textContent!==text)breadcrumbs.textContent=text}
  if(S.page==='settings')prepareSettings();
 }
 function prepareSettings(){
  const root=byId('content'),shortcuts=root.querySelector('.settings-shortcuts');if(!shortcuts||byId('wsSettingsFilter'))return;
  const bar=document.createElement('div');bar.className='toolbar';bar.innerHTML='<label for="wsSettingsFilter">查找设置</label><input id="wsSettingsFilter" placeholder="输入设置名称或用途"><label for="wsSettingsCategory">分类</label><select id="wsSettingsCategory"><option value="">全部设置</option><option value="订阅">订阅访问</option><option value="服务器">服务器与监控</option><option value="账号">账号与通知</option><option value="外观">外观与 AI</option></select>';
  shortcuts.before(bar);const cards=[...shortcuts.children];cards.forEach(c=>{const t=c.textContent;c.dataset.category=/Agent|监控/.test(t)?'服务器':/订阅|DNS|流量/.test(t)?'订阅':/用户|通知/.test(t)?'账号':'外观'});
  const filter=()=>{const q=byId('wsSettingsFilter').value.trim().toLowerCase(),category=byId('wsSettingsCategory').value;cards.forEach(c=>c.hidden=!!((q&&!c.textContent.toLowerCase().includes(q))||(category&&c.dataset.category!==category)))};byId('wsSettingsFilter').oninput=filter;byId('wsSettingsCategory').onchange=filter;
 }
 function navigated(page){
  if(!replay&&location.hash!=='#'+page)history.pushState({page},'',location.pathname+location.search+'#'+page);
  const main=byId('appMain');main?.classList.toggle('ws-ai-page',page==='assistant');document.body.classList.toggle('ws-ai-docked',page==='assistant');
  if(pendingFrame)cancelAnimationFrame(pendingFrame);pendingFrame=requestAnimationFrame(preparePage);
 }
 async function dockAI(){
  const root=byId('content'),box=byId('aiFloatWindow');root.innerHTML='<section id="wsAIHost" class="ws-ai-page" aria-label="AI 工作区"></section>';
  byId('wsAIHost').append(box);box.classList.remove('ai-maximized');await aiOpenWindow();if(S.page==='assistant')box.classList.remove('hidden');
 }
 function undockAI(){const box=byId('aiFloatWindow');if(box.closest('#content')){document.body.append(box);box.classList.add('hidden');byId('aiLauncher').setAttribute('aria-expanded','false')}}
 function addServer(){openModal('添加服务器',`<p class="muted">选择接入方式，已有服务器和节点配置保持原状。</p><div class="ws-next-actions"><button class="btn primary" id="wsAddAgent">复制命令接入 Agent</button><p class="hint">在服务器执行同一条命令，自动登记 hostname 并上报硬件监控。</p><button class="btn" id="wsAddSSH">通过 SSH 添加服务器</button><p class="hint">适用于部署内核、管理节点和中转，需要 SSH 凭据。</p><button class="btn" id="wsAddExisting">接入现有面板或内核</button><p class="hint">连接已经运行的 3x-ui、Xray 或 sing-box。</p><button class="btn" id="wsAddProbe">从探针同步服务器</button></div>`);byId('wsAddAgent').onclick=()=>{closeModal();void go('agentEnrollManager')};byId('wsAddSSH').onclick=()=>serverForm();byId('wsAddExisting').onclick=()=>serverForm('',true);byId('wsAddProbe').onclick=()=>{closeModal();void go('probeSync')}}
 window.WorkspaceUI={search,prepareEditor,preparePage,navigated,dockAI,undockAI,addServer};
 byId('workspaceSearch').onclick=()=>search();
 window.addEventListener('popstate',()=>{const page=location.hash.slice(1);if(!S.role||S.role==='user'||!Object.hasOwn(pageInfo,page))return;replay=true;Promise.resolve(go(page)).catch(e=>notice(e.message)).finally(()=>replay=false)});
 document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'&&S.role==='admin'){e.preventDefault();if(!document.querySelector('dialog[open]'))search()}});
 const observer=new MutationObserver(()=>{if(pendingFrame)cancelAnimationFrame(pendingFrame);pendingFrame=requestAnimationFrame(()=>{pendingFrame=0;preparePage()})});
 observer.observe(byId('content'),{childList:true,subtree:true});observer.observe(byId('modalBody'),{childList:true,subtree:true});preparePage();
})();
