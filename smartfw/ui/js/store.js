/*Global event emmiter and State container*/

export const store = new (class extends EventTarget {
    #state = {blocked:new Set(), threshold:-0.25, alive:true}
    get(k){ return this.#state[k]; }
    set(k,v){
        this.#state[k]=v;
        this.dispatchEvent(new CustomEvent(k,{detail:v}));
    }
})