const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const host=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html);});
 await new Promise(resolve=>host.listen(0,'127.0.0.1',resolve));
 try{
  const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.goto('http://127.0.0.1:'+host.address().port+'/');
  await page.evaluate(()=>{
   $('boot').classList.add('hidden');$('login').classList.add('hidden');$('app').classList.remove('hidden');
   S.profile='clash';S.page='servers';S.serverId='server-a';
   S.remoteRows=[{id:1,port:24001,protocol:'vless',remark:'node',enable:true,editToken:'a'.repeat(64),shareLinks:['vless://fixture'],clientStats:[{email:'fixture'}],settings:{clients:[{id:'user-id',email:'fixture'}]}}];
   window.calls=[];window.refreshes=0;window.alerts=[];
   api=async(url,opt)=>{window.calls.push({url,method:opt.method,body:JSON.parse(opt.body)});return {updated:true};};
   serverNodes=async()=>{window.refreshes++};notice=()=>{};alert=text=>window.alerts.push(text);confirm=()=>true;
   remoteNodeEdit(1);
  });
  const raw=await page.$eval('#remoteJson',n=>JSON.parse(n.value));
  assert(!('editToken' in raw));assert(!('shareLinks' in raw));assert(!('clientStats' in raw));assert.equal(raw.settings.clients[0].id,'user-id');
  await page.evaluate(()=>{S.serverId='server-b';$('remoteEdit').requestSubmit();});
  await page.waitForFunction(()=>window.calls.length===1);
  let calls=await page.evaluate(()=>window.calls);
  assert.equal(calls[0].body.serverId,'server-a');assert.equal(calls[0].body.expectedIdentity,'a'.repeat(64));assert.equal(calls[0].body.inboundId,1);
  assert.equal(await page.evaluate(()=>window.refreshes),0,'late save refreshed a different server');
  await page.evaluate(async()=>{S.serverId='server-a';await remoteNodeToggle(1);await remoteNodeDelete(1);});
  calls=await page.evaluate(()=>window.calls);assert.equal(calls[1].body.inbound.enable,false);assert.equal(Object.keys(calls[1].body.inbound).length,1);
  for(const call of calls){assert.equal(call.body.serverId,'server-a');assert.equal(call.body.expectedIdentity,'a'.repeat(64));}
  assert.equal(calls[2].method,'DELETE');
  await page.evaluate(async()=>{delete S.remoteRows[0].editToken;await remoteNodeToggle(1);});
  calls=await page.evaluate(()=>window.calls);assert.equal(calls[3].body.inbound.protocol,'vless','legacy Python toggle lost full config');assert.equal(calls[3].body.inbound.port,24001);
  await page.evaluate(()=>{S.remoteRows[0].editToken='b'.repeat(64);api=async()=>{throw Error('入站配置已变化，请刷新列表后重新编辑')};remoteNodeEdit(1);$('remoteEdit').requestSubmit();});
  await page.waitForFunction(()=>$('remoteError')?.textContent.includes('配置已变化'));
  assert.equal(await page.$eval('#remoteSave',n=>n.disabled),false);
  await page.evaluate(()=>{api=()=>new Promise(resolve=>{window.finishSave=resolve});$('remoteEdit').requestSubmit();closeModal();openModal('新窗口','<p id="newDialog">保留此窗口</p>');window.finishSave({updated:true});});
  await page.waitForFunction(()=>window.refreshes===4);assert(await page.$('#newDialog'),'late save closed a newer dialog');assert.deepEqual(errors,[]);
  await page.evaluate(()=>{
   window.calls=[];
   S.remoteRows=[{id:1,editToken:'edit',editFields:{remark:'fixture',port:24001,xhttpPath:'/old',xhttpMode:'stream-up'}},
                 {id:2,deletePending:true,deleteToken:'delete'}];
   api=async(url,opt)=>{calls.push({url,method:opt.method,body:JSON.parse(opt.body)});return {updated:true}};
   remoteNodeEditManaged(1);
   $('coreInboundEdit').elements.xhttpPath.value='/new';
   $('coreInboundEdit').elements.xhttpMode.value='packet-up';
   $('coreInboundEdit').requestSubmit();
  });
  await page.waitForFunction(()=>calls.length===1);
  await page.evaluate(()=>remoteNodeDelete(2));
  calls=await page.evaluate(()=>window.calls);
  assert.deepEqual(calls[0].body.inbound,{xhttpPath:'/new',xhttpMode:'packet-up'});
  assert.equal(calls[1].body.expectedIdentity,'delete');assert.equal(calls[1].method,'DELETE');
  await page.evaluate(()=>{
   S.remoteRows[0].editPending=true;
   S.remoteRows[0].editPatch={xhttpPath:'/new',xhttpMode:'packet-up'};
   remoteNodeEditManaged(1);$('coreInboundEdit').requestSubmit();
  });
  await page.waitForFunction(()=>calls.length===3);
  calls=await page.evaluate(()=>window.calls);
  assert.deepEqual(calls[2].body.inbound,calls[0].body.inbound,'disabled retry fields lost original payload');
  const invalid=await page.evaluate(()=>{
   S.remoteRows=[{id:3,editToken:'grpc-edit',editFields:{remark:'grpc',port:24002,grpcService:'vpn'}}];
   remoteNodeEditManaged(3);
   const input=$('coreInboundEdit').elements.grpcService;input.value='/wrong';
   $('coreInboundEdit').requestSubmit();return input.checkValidity();
  });
  assert.equal(invalid,false);assert.equal(await page.evaluate(()=>calls.length),3);
  await page.evaluate(()=>{$('coreInboundEdit').elements.grpcService.value='vpn-new_1';$('coreInboundEdit').requestSubmit()});
  await page.waitForFunction(()=>calls.length===4);
  calls=await page.evaluate(()=>window.calls);assert.deepEqual(calls[3].body.inbound,{grpcService:'vpn-new_1'});
  assert.deepEqual(errors,[]);
  console.log('PASS: edit/toggle/delete preserve identity; XHTTP edits and retries preserve path/mode; pending deletes use delete token');
 }finally{await browser.close();await new Promise(resolve=>host.close(resolve));}
})().catch(error=>{console.error(error);process.exit(1)});
