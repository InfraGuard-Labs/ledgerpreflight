const { chromium } = require('playwright');
(async()=>{
  const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
  const page=await browser.newPage({viewport:{width:1440,height:1000}});
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('file:///dist/example-report.html');
  await page.screenshot({path:'/dist/example-report-desktop.png',fullPage:true});
  if(await page.locator('body').evaluate(el=>el.scrollWidth>window.innerWidth))throw Error('Desktop horizontal overflow');
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:'/dist/example-report-mobile.png',fullPage:true});
  if(await page.locator('body').evaluate(el=>el.scrollWidth>window.innerWidth))throw Error('Mobile horizontal overflow');
  if(errors.length)throw Error(errors.join('\n'));
  console.log('Offline report desktop/mobile render passed; zero browser errors or horizontal overflow.');
  await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
