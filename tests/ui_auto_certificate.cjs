const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN,headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const host=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html)});await new Promise(r=>host.listen(0,'127.0.0.1',r));
 try{
  const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));await page.goto('http://127.0.0.1:'+host.address().port+'/');
  async function setup(mode='success'){
   await page.evaluate(mode=>{
    $('boot').classList.add('hidden');$('login').classList.add('hidden');$('app').classList.remove('hidden');S.profile='owned-profile';S.serverId='server';S.page='nodes';S.remoteRows=[];S.idempotentCreate=true;S.remoteServer={installType:'3x-ui',certificateDomains:['node.example.com']};window.calls=[];
    notice=()=>{};reload=async()=>{};
    api=async(url,opt={})=>{calls.push({url,body:opt.body&&JSON.parse(opt.body),headers:opt.headers});if(url==='/servers/certificates')return {job:{id:'job',status:mode==='fail'?'failed':mode==='cancel'?'queued':'succeeded',domain:'node.example.com',error:'TCP 80 已被占用'}};if(url.startsWith('/servers/certificates?'))return {job:{id:'job',status:'succeeded',domain:'node.example.com'}};if(url==='/servers/users'){if(mode==='retry'&&calls.filter(x=>x.url===url).length===1)throw Error('创建结果待核对');return {shareLinks:['redacted'],inbound:{id:1}};}throw Error(url);};
    remoteNodeForm(false);
   },mode);
  }
  for(const width of [1440,390]){
   await page.setViewport({width,height:1000});await setup();
   assert.equal(await page.$eval('#rnSniTest',e=>!e.classList.contains('hidden')),true);
   assert.ok(await page.evaluate(()=>sniCandidates().length>=42));
   await page.select('#rnTemplate','hysteria2');
   assert.equal(await page.$eval('#rnSni',e=>e.value),'node.example.com');
   assert.equal(await page.$eval('#rnSniTest',e=>e.classList.contains('hidden')),true);
   assert.equal(await page.$eval('#rnCertMode',e=>e.value),'auto');
   assert.equal(await page.$eval('#rnManualCertFields',e=>e.classList.contains('hidden')),true);
   await page.select('#rnCertMode','manual');assert.equal(await page.$eval('#rnCert',e=>e.required),true);
   await page.select('#rnCertMode','auto');await page.type('#rnName','HY2');await page.click('#rnSave');await page.waitForFunction(()=>calls.some(x=>x.url==='/servers/users'));
   const call=await page.evaluate(()=>calls.find(x=>x.url==='/servers/users'));assert.equal(call.body.certificateJobId,'job');assert.equal(call.headers['X-Profile'],'owned-profile');
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2),true);
  }
  await setup();await page.evaluate(()=>{
   S.remoteServer.installType='sing-box';
   const base=api;api=async(url,opt)=>{const result=await base(url,opt);return url==='/servers/users'?{...result,bound:true}:result};
   remoteNodeForm(false);
  });
  await page.select('#rnTemplate','vless-reality');
  assert.equal(await page.$eval('#rnSniTest',e=>e.classList.contains('hidden')),false);
  await page.type('#rnName','sing-box Reality');await page.click('#rnSave');
  await page.waitForFunction(()=>calls.some(x=>x.url==='/servers/users'));
  assert.equal(await page.evaluate(()=>calls.some(x=>x.url==='/servers/certificates')),false);
  assert.equal(await page.evaluate(()=>calls.find(x=>x.url==='/servers/users').body.template),'vless-reality');
  for(const kind of ['xray','sing-box']){
   for(const template of ['vmess-ws-tls','vless-tcp-tls','vmess-tcp-tls','trojan-ws-tls','trojan-grpc-tls']){
   await setup();await page.evaluate(kind=>{
    S.remoteServer.installType=kind;
    const base=api;api=async(url,opt)=>{const result=await base(url,opt);return url==='/servers/users'?{...result,bound:true}:result};
    remoteNodeForm(false);
   },kind);
   await page.select('#rnTemplate',template);
   assert.equal(await page.$eval('#rnWsField',e=>e.classList.contains('hidden')),!template.includes('-ws-'));
   assert.equal(await page.$eval('#rnGrpcField',e=>e.classList.contains('hidden')),!template.includes('-grpc-'));
   assert.equal(await page.$eval('#rnSni',e=>e.value),'node.example.com');
   assert.equal(await page.$eval('#rnPort',e=>e.value),'');
   await page.type('#rnName','VMess WebSocket');await page.$eval('#rnPath',e=>e.value='/owned-ws');await page.click('#rnSave');
   await page.waitForFunction(()=>calls.some(x=>x.url==='/servers/users'));
   const call=await page.evaluate(()=>calls.find(x=>x.url==='/servers/users'));
   assert.equal(call.body.template,template);assert.equal(call.body.path,'/owned-ws');assert.equal(call.body.certificateJobId,'job');
   if(template.includes('-grpc-'))assert.equal(call.body.grpcService,'vpn');
   }
  }
  for(const kind of ['xray','sing-box']) {
   for(const template of ['ss2022-aes-128','ss2022-aes-256',...(kind==='xray'?['ss-aes-128-gcm','ss-aes-256-gcm','ss-chacha20-poly1305']:[])]) {
    await setup();await page.evaluate(kind=>{S.remoteServer.installType=kind;const base=api;api=async(url,opt)=>{const result=await base(url,opt);return url==='/servers/users'?{...result,bound:true}:result};remoteNodeForm(false);},kind);
    await page.select('#rnTemplate',template);
    assert.equal(await page.$eval('#rnSniFields',e=>e.classList.contains('hidden')),true);
    assert.equal(await page.$eval('#rnTlsFields',e=>e.classList.contains('hidden')),true);
    assert.equal(await page.$eval('#rnSni',e=>e.required),false);
    await page.type('#rnName','SS2022');await page.click('#rnSave');await page.waitForFunction(()=>calls.some(x=>x.url==='/servers/users'));
    assert.equal(await page.evaluate(()=>calls.some(x=>x.url==='/servers/certificates')),false);
    assert.equal(await page.evaluate(()=>calls.find(x=>x.url==='/servers/users').body.template),template);
   }
  }
  await setup();assert.equal(await page.evaluate(()=>Array.from($('rnTemplate').options).some(x=>x.value.startsWith('ss2022-'))),false);
  await page.evaluate(()=>{S.remoteServer.installType='sing-box';remoteNodeForm(false)});assert.equal(await page.evaluate(()=>Array.from($('rnTemplate').options).some(x=>x.value.startsWith('ss2022-'))),true);
  assert.equal(await page.evaluate(()=>Array.from($('rnTemplate').options).some(x=>x.value.startsWith('ss-'))),false);
  assert.deepEqual(await page.evaluate(()=>[remoteSupportsIndependentUser({protocol:'shadowsocks',provisionable:true}),remoteSupportsIndependentUser({protocol:'shadowsocks'}),remoteSupportsIndependentUser({protocol:'shadowsocks',provisionable:false})]),[true,false,false]);
  for(const changed of [false,true]) {
   const result=await page.evaluate(async changed=>{
    S.profile='owned-profile';S.page='nodes';S.data={nodes:[{index:0,name:'SS2022',type:'ss',port:23456,server:'example.com',config:{cipher:'2022-blake3-aes-128-gcm',password:'root:user'}}],profile:{traffic:{bindings:[{scope:'user',status:'active',serverId:'server',inboundId:17,importedNames:['SS2022']}]}}};
    const row={id:17,protocol:'shadowsocks',provisionable:true,enable:true,port:23456,settings:{method:'2022-blake3-aes-128-gcm',password:changed?'changed-root':'root',clients:[{email:'owner',password:'user'}]}};
    api=async()=>({inbounds:[row],server:{host:'example.com'}});let linked=false;remoteNodeLinks=()=>{linked=true};
    await nodeSubscriptionImport(0);return {linked,error:$('nodeSubscriptionError').textContent};
   },changed);
   assert.equal(result.linked,!changed);assert.equal(result.error.length>0,changed);
  }
  for(const changed of [false,true]) {
   const result=await page.evaluate(async changed=>{
    S.profile='owned-profile';S.data={nodes:[{index:0,name:'SS2022',type:'ss',port:23456,server:'example.com',config:{cipher:'2022-blake3-aes-128-gcm',password:'root:user'}}],profile:{traffic:{bindings:[{scope:'user',status:'active',serverId:'server',inboundId:17,importedNames:['SS2022']}]}}};
    const row={id:17,protocol:'shadowsocks',provisionable:true,enable:true,coreStatus:'present',port:23456,shareLinks:[changed?'ss://different@example.com:23456#peer':'ss://valid@example.com:23456#peer']};
    api=async url=>url.startsWith('/nodes/share')?{uri:'ss://valid@example.com:23456#renamed'}:{inbounds:[row],server:{host:'example.com'},readOnly:true};let linked=false;remoteNodeLinks=()=>{linked=true};
    await nodeSubscriptionImport(0);return {linked,error:$('nodeSubscriptionError').textContent};
   },changed);
   assert.equal(result.linked,!changed);assert.equal(result.error.length>0,changed);
  }
  await setup('fail');await page.select('#rnTemplate','hysteria2');await page.type('#rnName','HY2');await page.click('#rnSave');await page.waitForFunction(()=>$('remoteError').textContent.includes('TCP 80'));
  assert.equal(await page.evaluate(()=>calls.some(x=>x.url==='/servers/users')),false);
  await setup('retry');await page.select('#rnTemplate','hysteria2');await page.type('#rnName','HY2');await page.click('#rnSave');await page.waitForFunction(()=>$('remoteError').textContent.includes('待核对'));
  assert.equal(await page.$eval('#rnName',e=>e.disabled),true);assert.equal(await page.$eval('#rnSave',e=>e.textContent),'重试核对');
  await page.evaluate(()=>$('rnName').value='changed programmatically');await page.click('#rnSave');await page.waitForFunction(()=>calls.filter(x=>x.url==='/servers/users').length===2);
  let retryCalls=await page.evaluate(()=>calls.filter(x=>x.url==='/servers/users'));assert.deepEqual(retryCalls[0].body,retryCalls[1].body);assert.match(retryCalls[0].body.operationId,/^[a-f0-9]{32}$/);assert.equal(await page.evaluate(()=>calls.filter(x=>x.url==='/servers/certificates').length),1,'retry started another certificate job');
  await setup('retry');await page.evaluate(()=>{S.idempotentCreate=false;});await page.select('#rnTemplate','hysteria2');await page.type('#rnName','HY2');await page.click('#rnSave');await page.waitForFunction(()=>$('remoteError').textContent.includes('待核对'));assert.equal(await page.$eval('#rnName',e=>e.disabled),false,'Python fallback was locked as if it supported idempotency');assert.equal(await page.$eval('#rnSave',e=>e.textContent),'重新创建');
  await setup();await page.evaluate(()=>{S.serverId='other-server';$('remoteNodeForm').requestSubmit();});assert.equal(await page.evaluate(()=>calls.length),0,'created on a server selected after opening the form');
  await setup('cancel');await page.select('#rnTemplate','hysteria2');await page.type('#rnName','HY2');await page.click('#rnSave');await page.waitForFunction(()=>calls.length>0);await page.evaluate(()=>closeModal());await new Promise(r=>setTimeout(r,1800));
  assert.equal(await page.evaluate(()=>calls.some(x=>x.url==='/servers/users')),false);
  assert.deepEqual(errors,[]);console.log('Auto certificate UI: modes, owned SNI, Reality candidates, scoped creation, failure and cancel PASS');
 }finally{await browser.close();await new Promise(r=>host.close(r));}
})().catch(e=>{console.error(e);process.exit(1)});
