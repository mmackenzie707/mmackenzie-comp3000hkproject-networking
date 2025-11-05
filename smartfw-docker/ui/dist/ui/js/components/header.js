import {store} from '../store.js';

export function initHeader(){
    const root = document.getElementById('header');
    root.innerHTML =`
        <span>SmartFW HUB</span>
        <span class="status" id="status"></span>`;
    store.addEventListener('alive', e=> {
        root.querySelector('.status').classList.toggle('off',!e.detail);
    });
}