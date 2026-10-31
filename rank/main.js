// Rank: daftar tier, helper rank, dan avatar ring
const TIER_NEWBIE={key:'newbie',min:0,name:'Newbie',ring:null,deco:null,benefits:["Akses penuh Global Chat", "Kirim teks, foto, dan sticker"]};
const TIERS=[TIER_NEWBIE,TIER_JUNIOR,TIER_SENIOR,TIER_PRO,TIER_MASTER,TIER_LEGENDARY,TIER_ETERNAL];
const RANK_BENEFITS=Object.fromEntries(TIERS.map(t=>[t.key,t.benefits||[]]));
function tierOf(exp){const v=Number(exp)||0;let t=TIERS[0];for(const x of TIERS)if(v>=x.min)t=x;return t;}
function tierAvatar(img,exp){const t=tierOf(exp);let w=img.parentElement;if(!w||!w.classList.contains('av-wrap')){const nw=document.createElement('span');if(img.parentNode)img.parentNode.insertBefore(nw,img);nw.appendChild(img);w=nw;}w.className='av-wrap';w.dataset.tier=t.key;w.querySelectorAll('.av-ring,.av-deco').forEach(n=>n.remove());if(t.ring){const r=document.createElement('span');r.className='av-ring';r.style.background=t.ring==='rainbow'?'conic-gradient(#ff3b3b,#ff9f1a,#ffe600,#2ee66b,#2ec5ff,#7b5cff,#ff3bd4,#ff3b3b)':t.ring;w.insertBefore(r,img);}if(t.deco){const d=document.createElement('i');d.className='fa-solid '+t.deco+' av-deco';w.appendChild(d);}img.classList.add('av-img');return w;}
function rankTagHtml(email){const t=tierOf(expOf(email));return '<span class="chat-rank rk-'+t.key+'">['+escHtml(t.name)+']</span>';}
