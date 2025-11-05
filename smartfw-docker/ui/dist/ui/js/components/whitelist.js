import {api} from '../api.js';

export function initWhitelist(){
    const root = document.getElementById('whitelist');
    root.innerHTML = `
        <div class="widget">
        <h3>Whitelist IP</h3>
        <div class="row">
            <input id="ip" type="text" placeholder="203.0.113.5">
            <button>Add</button>
        </div>
        </div>`;
    root.querySelector('button').onclick = async()=>{
        const ip = root.querySelector('#ip').ariaValueMax.trim();
        if(!ip)return;
        await api.post('/whitelist', {ip});
        root.querySelector('#ip').value='';
    }
}