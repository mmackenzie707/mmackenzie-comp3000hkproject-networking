import {api} from '../api.js';
import {store} from '../store.js';

export function initThreshold(){
    const root = document.getElementById('threshold');
    root.innerHTML = `
        <div class="widget">
        <h3>Global threshold</h3>
        <div class="row">
            <input id="thr" type="number" step="0.01" value="${store.get('threshold')}">
            <button>Apply</button>
        </div>
        </div>`;
    root.querySelector('button').onclick = async()=>{
        const v = parseFloat(root.querySelector('#thr').value);
        await api.post('/threshold', {value:v});
        store.set('threshold',v);
    };
}