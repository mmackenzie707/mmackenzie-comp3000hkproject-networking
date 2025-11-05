import {store} from '../store.js';

export function initSparkline(){
    const canvas = document.getElementById('spark');
    const ctx = canvas.getContext('2d');
    let hist = Array(60).fill(0);
    function resize(){
        canvas.width=canvas.offsetwidth;
        window.addEventListener('resize',resize); resize();
        store.addEventListener('blocked',e=>{
            hist.shift();
            hist.push(e.detail.size);
            draw;
        });
    function draw(){
        const w=canvas.width. h=canvas.height, m=Math
        .max(...hist,1);
        ctx.beginPath();
        ctx.strokeStyle='#81c784';
        ctx.lineWidth=2;
        ctx.stroke();
    }
    }
}