const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN,headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const host=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html)});await new Promise(resolve=>host.listen(0,'127.0.0.1',resolve));
 try{
  const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));await page.goto('http://127.0.0.1:'+host.address().port+'/');
  await page.evaluate(()=>{
   $('boot').classList.add('hidden');$('login').classList.add('hidden');$('app').classList.remove('hidden');S.serverId='server';S.profile='clash';S.page='nodes';S.remoteServer={installType:'3x-ui'};S.idempotentCreate=true;
   window.calls=[];window.legacyImports=0;notice=()=>{};alert=()=>{};importRemoteLinks=async()=>{window.legacyImports++};
   api=async(url,opt)=>{if(url!=='/servers/relay')throw Error('Unexpected '+url);window.calls.push(JSON.parse(opt.body));if(window.calls.length===1)throw Error('中转请求结果待核对');return {bound:true,shareLinks:['fixture'],inbound:{id:1}}};
   remoteNodeForm(true);$('rnName').value='relay';$('rnLanding').value='socks5://fixture:password@example.com:1080';$('remoteNodeForm').requestSubmit();
  });
  await page.waitForFunction(()=>$('remoteError')?.textContent.includes('待核对'));assert.equal(await page.$eval('#rnLanding',n=>n.disabled),true);
  await page.click('#rnSave');await page.waitForFunction(()=>window.calls.length===2);
  const calls=await page.evaluate(()=>window.calls);assert.deepEqual(calls[0],calls[1]);assert.match(calls[0].operationId,/^[0-9a-f]{32}$/);assert.equal(await page.evaluate(()=>window.legacyImports),0);assert.deepEqual(errors,[]);
  await page.evaluate(()=>{
   S.remoteServer={installType:'sing-box'};window.calls=[];window.scans=[];
   openSniScanner=(serverId,targetId)=>window.scans.push({serverId,targetId});
   remoteNodeForm(true);
  });
  assert.equal(await page.$eval('#rnSniFields',e=>e.classList.contains('hidden')),true);
  assert.equal(await page.$eval('#rnSni',e=>e.required),false);
  await page.select('#rnRelayTemplate','vless-reality');
  assert.equal(await page.$eval('#rnSniFields',e=>e.classList.contains('hidden')),false);
  assert.equal(await page.$eval('#rnSni',e=>e.required),true);
  await page.click('#rnSniTest');
  assert.deepEqual(await page.evaluate(()=>window.scans),[{serverId:'server',targetId:'rnSni'}]);
  await page.evaluate(()=>{
   $('rnName').value='sing-reality-relay';$('rnLanding').value='socks5://fixture:password@example.com:1080';
   $('rnSni').value='example.com';$('rnSni').dataset.sniVerified='example.com';$('rnSni').dataset.sniAddress='1.1.1.1';
   $('remoteNodeForm').requestSubmit();
  });
  await page.waitForFunction(()=>$('remoteError')?.textContent.includes('待核对'));
  assert.equal(await page.$eval('#rnRelayTemplate',e=>e.disabled),true);
  await page.evaluate(()=>$('rnRelayTemplate').value='vmess-tcp');
  await page.click('#rnSave');await page.waitForFunction(()=>window.calls.length===2);
  const singCalls=await page.evaluate(()=>window.calls);
  assert.deepEqual(singCalls[0],singCalls[1]);assert.equal(singCalls[0].template,'vless-reality');
  assert.equal(singCalls[0].sniAddress,'1.1.1.1');assert.equal(singCalls[0].sniVerified,true);
  assert.deepEqual(errors,[]);
  console.log('PASS: relay retries preserve operation/config; native bound result skips legacy import');
 }finally{await browser.close();await new Promise(resolve=>host.close(resolve))}
})().catch(error=>{console.error(error);process.exit(1)});
