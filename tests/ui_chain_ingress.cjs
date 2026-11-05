const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN,headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const host=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html)});
 await new Promise(resolve=>host.listen(0,'127.0.0.1',resolve));
 try{
  const page=await browser.newPage(),errors=[];page.on('pageerror',error=>errors.push(String(error)));
  await page.goto('http://127.0.0.1:'+host.address().port+'/');
  await page.evaluate(()=>{
   $('boot').classList.add('hidden');$('login').classList.add('hidden');$('app').classList.remove('hidden');
   S.profile='clash';S.page='chains';S.idempotentCreate=true;S.data={groups:[],nodes:[]};
   ordinaryNodes=()=>['xray','sing','exit'].map(name=>({name,config:{server:name+'.example.net'}}));
   window.calls=[];window.scans=[];notice=()=>{};reload=async()=>{};
   openSniScanner=(serverId,targetId)=>scans.push({serverId,targetId});
   api=async(url,opt)=>{
    if(url==='/servers')return {servers:['xray','sing','exit'].map(id=>({id,host:id+'.example.net',installType:id==='sing'?'sing-box':'xray'}))};
    if(!['/chains','/failovers'].includes(url))throw Error('Unexpected '+url);
    calls.push({url,body:JSON.parse(opt.body)});
    if(calls.filter(call=>call.url===url).length===1)throw Error('创建结果待核对');
    return {bound:true,status:'active'};
   };
  });
  await page.evaluate(()=>chainModal());
  await page.select('#chainMode','server');await page.select('#chainEntry','sing');await page.select('#chainExit','exit');
  assert.equal(await page.$eval('#chainSingTemplateField',e=>e.classList.contains('hidden')),false);
  assert.equal(await page.$eval('#chainSingTemplate',e=>e.value),'vless-reality');
  assert.equal(await page.$eval('#chainSni',e=>e.required),true);await page.click('#chainSniTest');
  await page.select('#chainSingTemplate','vmess-tcp');
  assert.equal(await page.$eval('#chainSniTest',e=>e.classList.contains('hidden')),true);
  assert.equal(await page.$eval('#chainSni',e=>e.disabled),true);
  await page.select('#chainSingTemplate','vless-reality');
  await page.type('#chainName','owned-chain');await page.evaluate(()=>$('editForm').requestSubmit());
  await page.waitForFunction(()=>$('formError')?.textContent.includes('待核对'));
  assert.equal(await page.$eval('#chainSingTemplate',e=>e.disabled),true);
  await page.evaluate(()=>{$('chainName').value='changed';$('chainSingTemplate').value='vmess-tcp'});
  await page.click('#editForm button.primary');await page.waitForFunction(()=>calls.filter(call=>call.url==='/chains').length===2);
  const chain=await page.evaluate(()=>calls.filter(call=>call.url==='/chains'));
  assert.deepEqual(chain[0].body,chain[1].body);assert.equal(chain[0].body.singBoxTemplate,'vless-reality');
  assert.match(chain[0].body.operationId,/^[a-f0-9]{32}$/);

  await page.evaluate(()=>failoverModal());
  const scans=await page.$$('.foScan');assert.equal(scans.length,2);
  assert.equal(await scans[1].evaluate(e=>e.classList.contains('hidden')),false);
  await page.select('#foSingTemplate','vmess-tcp');
  assert.equal(await scans[0].evaluate(e=>e.classList.contains('hidden')),false);
  assert.equal(await scans[1].evaluate(e=>e.classList.contains('hidden')),true);
  await page.select('#foSingTemplate','vless-reality');await scans[1].click();
  assert.deepEqual(await page.evaluate(()=>window.scans),[{serverId:'sing',targetId:'chainSni'},{serverId:'sing',targetId:'foSni'}]);
  await page.type('#foName','owned-failover');await page.evaluate(()=>$('failoverForm').requestSubmit());
  await page.waitForFunction(()=>$('formError')?.textContent.includes('待核对'));
  assert.equal(await page.$eval('#foSingTemplate',e=>e.disabled),true);
  await page.evaluate(()=>{$('foName').value='changed';$('foSingTemplate').value='vmess-tcp'});
  await page.click('#failoverForm button.primary');await page.waitForFunction(()=>calls.filter(call=>call.url==='/failovers').length===2);
  const failover=await page.evaluate(()=>calls.filter(call=>call.url==='/failovers'));
  assert.deepEqual(failover[0].body,failover[1].body);assert.equal(failover[0].body.singBoxTemplate,'vless-reality');
  assert.deepEqual(failover[0].body.entries,['xray','sing']);assert.deepEqual(errors,[]);
  await page.evaluate(async()=>{
   api=()=>new Promise(resolve=>window.finishServerList=resolve);
   const opening=chainModal();S.profile='other';finishServerList({servers:[]});await opening;
  });
  assert.equal(await page.$('#editForm'),null,'a delayed server list opened a chain for a different subscription');
  console.log('PASS: chain/failover sing-box protocol selection, per-server SNI scan and immutable retries');
 }finally{await browser.close();await new Promise(resolve=>host.close(resolve))}
})().catch(error=>{console.error(error);process.exit(1)});
