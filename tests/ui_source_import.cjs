// Browser contract tests use isolated mock subscriptions; no remote network.
const puppeteer=require('puppeteer-core'),fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert/strict');
(async()=>{
 const browser=await puppeteer.launch({executablePath:process.env.MXIOC_CHROMIUM_BIN||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 const html=fs.readFileSync(path.resolve(__dirname,'..','index.html'),'utf8').replace('void bootstrap();','');
 const server=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html; charset=utf-8');res.end(html)});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{
  const page=await browser.newPage(),errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.goto('http://127.0.0.1:'+server.address().port+'/');
  await page.evaluate(()=>{
   $('boot').classList.add('hidden');$('login').classList.add('hidden');$('app').classList.remove('hidden');
   S.page='subscriptions';S.profile='clash';S.profiles=[{id:'clash',name:'A'},{id:'other',name:'B'}];
   S.data={nodes:[],groups:['Proxy','Other','Protected','广告拦截'].map(name=>({name,type:'select',config:{proxies:['DIRECT']}})),rules:[],profile:{name:'A',traffic:{configured:false,bindings:[]}}};
   window.sourceCalls=[];window.previewMode='normal';window.importMode='normal';
   api=async(url,opt={})=>{
    sourceCalls.push({url,opt});
    if(url==='/nodes/group-options')return {groups:['Proxy','Other']};
    if(url==='/import-subscription/preview'){
     if(previewMode==='wait')return new Promise(resolve=>window.resolvePreview=resolve);
     if(previewMode==='error')throw Error('订阅读取失败');
     return {total:2,protocols:{hysteria2:1,snell:1},skipped:[],groups:['Proxy','Other']};
    }
    if(url==='/import-subscription'){
     if(importMode==='wait')return new Promise(resolve=>window.resolveImport=resolve);
     return {ok:true,added:2,replaced:0,skipped:0,names:['HY','Snell']};
    }
    if(url==='/snapshot')return S.data;
    throw Error('unexpected API '+url);
   };
  });
  for(const width of [1280,390]){
   await page.setViewport({width,height:900});await page.evaluate(()=>subscriptions());
   assert.deepEqual(await page.$$eval('.importGroup',els=>els.map(e=>e.value)),['Proxy','Other']);
   assert.equal(await page.$$eval('.importGroup:checked',els=>els.length),2);
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2),'mobile page overflow');
   await page.$eval('#sourceSubUrl',e=>{e.value='https://source.example/sub?token=private';e.dispatchEvent(new Event('input'))});
   await page.click('#previewSub');await page.waitForFunction(()=>!$('confirmSubImport').disabled);
   await page.$eval('#subImportForm',e=>e.requestSubmit());
   await page.waitForFunction(()=>sourceCalls.some(x=>x.url==='/import-subscription')&&$('sourceSubUrl').value==='');
   const call=await page.evaluate(()=>sourceCalls.filter(x=>x.url==='/import-subscription').at(-1));
   assert.equal(call.opt.headers['X-Profile'],'clash');assert.deepEqual(JSON.parse(call.opt.body).groups,['Proxy','Other']);
  }
  await page.$eval('#sourceSubUrl',e=>{e.value='https://source.example/old';e.dispatchEvent(new Event('input'))});
  await page.click('#previewSub');await page.waitForFunction(()=>!$('confirmSubImport').disabled);
  await page.$eval('#sourceSubUrl',e=>{e.value='https://source.example/new';e.dispatchEvent(new Event('input'))});
  assert(await page.$eval('#confirmSubImport',e=>e.disabled),'editing URL kept old preview authorized');
  await page.evaluate(()=>{previewMode='wait'});await page.click('#previewSub');
  await page.waitForFunction(()=>typeof resolvePreview==='function');
  await page.evaluate(async()=>{S.profile='other';await subscriptions();resolvePreview({total:9,protocols:{snell:9},skipped:[],groups:[]})});
  assert(await page.$eval('#confirmSubImport',e=>e.disabled),'stale preview enabled another subscription');
  assert.equal(await page.$eval('#subImportForm',e=>e.dataset.profile),'other');
  await page.evaluate(()=>{previewMode='normal';importMode='wait'});
  await page.$eval('#sourceSubUrl',e=>{e.value='https://source.example/current';e.dispatchEvent(new Event('input'))});
  await page.click('#previewSub');await page.waitForFunction(()=>!$('confirmSubImport').disabled);
  await page.$eval('#subImportForm',e=>e.requestSubmit());await page.waitForFunction(()=>typeof resolveImport==='function');
  const snapshots=await page.evaluate(()=>sourceCalls.filter(x=>x.url==='/snapshot').length);
  await page.evaluate(async()=>{S.profile='clash';await subscriptions();resolveImport({ok:true,added:2,replaced:0})});
  assert.equal(await page.evaluate(()=>sourceCalls.filter(x=>x.url==='/snapshot').length),snapshots,'old import reloaded another profile');
  assert.equal(await page.$eval('#subImportForm',e=>e.dataset.profile),'clash');
  await page.evaluate(()=>{previewMode='error'});
  await page.$eval('#sourceSubUrl',e=>{e.value='https://source.example/fail';e.dispatchEvent(new Event('input'))});
  await page.click('#previewSub');await page.waitForFunction(()=>$('formError').textContent==='订阅读取失败');
  assert(await page.$eval('#confirmSubImport',e=>e.disabled));
  assert.deepEqual(errors,[]);
  console.log('PASS: source import desktop/mobile, allowed groups, preview/confirm contract, URL edits, stale profile responses and errors');
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve))}
})().catch(error=>{console.error(error);process.exitCode=1});
