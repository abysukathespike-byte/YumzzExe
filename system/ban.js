// Ban: cek status ban, notifikasi ban, dan dialog ban owner/admin
function isBanActive(u){return !!u&&!!u.banned&&(!u.ban_until||new Date(u.ban_until)>new Date());}
async function showBanNotice(u){const until=u.ban_until?new Date(u.ban_until).toLocaleString('id-ID'):'Permanen';await uiAlert('Alasan: '+(u.ban_reason||'-')+'\nBerakhir: '+until,'Akun kamu dibanned');}
function uiBanDialog(){return uiDialog((bx,done)=>{uiTitle(bx,'Ban user');
  const l1=document.createElement('div');l1.className='ui-lbl';l1.textContent='Alasan';bx.appendChild(l1);
  const sel=document.createElement('select');sel.className='ui-in';BAN_REASONS.forEach(x=>{const o=document.createElement('option');o.value=x;o.textContent=x;sel.appendChild(o);});bx.appendChild(sel);
  const note=document.createElement('input');note.className='ui-in';note.placeholder='Catatan tambahan (opsional)';note.maxLength=120;bx.appendChild(note);
  const l2=document.createElement('div');l2.className='ui-lbl';l2.textContent='Durasi';bx.appendChild(l2);
  const dur=document.createElement('select');dur.className='ui-in';BAN_DURATIONS.forEach((d,i)=>{const o=document.createElement('option');o.value=i;o.textContent=d[0];dur.appendChild(o);});bx.appendChild(dur);
  const r=uiRow(bx);r.appendChild(uiBtn('Batal','',()=>done(null)));
  r.appendChild(uiBtn('Ban','danger',()=>{const d=BAN_DURATIONS[+dur.value];const until=d[1]==null?null:new Date(Date.now()+d[1]*864e5).toISOString();const reason=sel.value+(note.value.trim()?' - '+note.value.trim():'');done({reason,until,label:d[0]});}));
});}
