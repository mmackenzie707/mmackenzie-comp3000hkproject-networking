import {store} from '../store.js';

export function initBlockedList(){
    const root = document.getElementById('blocked');
    root.innerHTML = `
    <div class="widget">
    <h3>Blocked IPs (<span id="c">0</span>)</h3>
    <ul id="list"></ul>
    </div>`;
    const listEl = root.querySelector('#list');
    const countEl = root.querySelector('#c');
    store.addEventListener('blocked', e=>{
        const blocked = [...e.detail];
        countEl.textContent = blocked.length;
        listEl.innerHTML = blocked.map(ip=> `<li><span class=ip>${ip}</span><small>auto unblock ~5 min</small></li>`).join('');
    });
}