const $ = id => document.getElementById(id);
const format = n => { const units=['B','KB','MB','GB']; let i=0; while(n>=1024&&i<3){n/=1024;i++;}return `${n.toFixed(i ? 1 : 0)} ${units[i]}`; };
const duration = n => n>=86400 ? `${Math.floor(n/86400)} 天` : `${Math.floor(n/3600)}h ${Math.floor(n%3600/60)}m`;
let last=null;
function showLogin(){ $('login').hidden=false; $('dashboard').hidden=true; last=null; }
function cell(row,text){const td=document.createElement('td');td.textContent=text;row.append(td);}
function draw(history){
  const svg=$('chart'); svg.replaceChildren(); const ns='http://www.w3.org/2000/svg';
  const rates=history.slice(1).map((p,i)=>{const a=history[i],dt=Math.max(p.time-a.time,.01);return {rx:Math.max(0,(p.rx-a.rx)/dt),tx:Math.max(0,(p.tx-a.tx)/dt)};});
  const max=Math.max(1024,...rates.flatMap(p=>[p.rx,p.tx]));
  for(let i=0;i<4;i++){const l=document.createElementNS(ns,'line');Object.entries({x1:0,x2:900,y1:i*44+4,y2:i*44+4,stroke:'#30382f','stroke-dasharray':'4 6'}).forEach(([k,v])=>l.setAttribute(k,v));svg.append(l);}
  for(const [key,color] of [['rx','#c4f081'],['tx','#90b6d0']]){if(!rates.length)continue;const l=document.createElementNS(ns,'polyline');l.setAttribute('points',rates.map((p,i)=>`${900-(rates.length-1-i)*900/59},${136-p[key]/max*126}`).join(' '));l.setAttribute('fill','none');l.setAttribute('stroke',color);l.setAttribute('stroke-width','2');l.setAttribute('vector-effect','non-scaling-stroke');svg.append(l);}
  $('chart-scale').textContent=`纵轴上限 ${format(max)}/s`;
}
async function refresh(){
  try{
    const r=await fetch('/api/status'); if(r.status===401){showLogin();return;} if(!r.ok)throw Error('获取状态失败'); const d=await r.json();
    $('login').hidden=true;$('dashboard').hidden=false;$('notice').hidden=!d.error;$('notice').textContent=d.error||'';
    $('health').textContent=d.running?'中继运行中':'中继未运行';$('light').classList.toggle('off',!d.running);
    $('count').textContent=d.clients.length;$('client-badge').textContent=d.clients.length;$('rx').textContent=format(d.bytes_rx);$('tx').textContent=format(d.bytes_tx);$('uptime').textContent=duration(d.uptime);$('port').textContent=`UDP ${d.port}`;
    $('access').textContent=d.allowlist_enabled?'◈ IP 白名单已启用':'◇ 未启用 IP 白名单';$('rejected').textContent=`白名单拒绝 ${d.rejected} 包`;
    const now=Date.now();if(last){const dt=(now-last.time)/1000;$('rx-rate').textContent=`${format(Math.max(0,(d.bytes_rx-last.rx)/dt))}/s · ${d.packets_rx} 包`;$('tx-rate').textContent=`${format(Math.max(0,(d.bytes_tx-last.tx)/dt))}/s · ${d.packets_tx} 包`;}
    last={time:now,rx:d.bytes_rx,tx:d.bytes_tx};const rows=$('client-rows');rows.replaceChildren();
    for(const c of d.clients){const tr=document.createElement('tr');[c.endpoint,c.virtual_ip||'等待学习',c.scope==='0'?'未进入会话':`0x${Number(c.scope).toString(16)}`,`${format(c.bytes_rx)} / ${format(c.bytes_tx)}`,`${c.idle_seconds.toFixed(0)} 秒前`].forEach(t=>cell(tr,t));rows.append(tr);}
    $('empty').hidden=d.clients.length>0;const logs=$('event-list');logs.replaceChildren();
    for(const event of [...d.events].reverse()){const el=document.createElement('div');el.className=`event ${event.level}`;const time=document.createElement('time');time.textContent=new Date(event.time*1000).toLocaleTimeString('zh-CN',{hour12:false});const msg=document.createElement('span');msg.textContent=event.message;el.append(time,msg);logs.append(el);}
    draw(d.history);$('updated').textContent=`更新于 ${new Date().toLocaleTimeString('zh-CN',{hour12:false})}`;
  }catch(e){$('notice').hidden=false;$('notice').textContent='连接中断，正在重试。';$('health').textContent='连接中断';$('light').classList.add('off');}
}
$('login-form').addEventListener('submit',async e=>{e.preventDefault();$('login-error').textContent='';try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:$('password').value})});const d=await r.json();if(!r.ok)throw Error(d.error);$('password').value='';await refresh();}catch(e){$('login-error').textContent=e.message;}});
$('logout').addEventListener('click',async()=>{await fetch('/api/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});showLogin();});
async function poll(){await refresh();setTimeout(poll,2000);}poll();
