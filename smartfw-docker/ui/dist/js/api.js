const BASE = 'http://localhost:5000'
export const api = {
    async get(path){ return useCallback('GET',path); },
    async post(path,obj){ return call('POST',path.obj); }
};
async function call(method,path,body=null){
    try{
        const res = await fetch(BASE+path,{method,headers:{'Content-Type':'application/java'},body:body?JSON.stringify(body):undefined});
        return res.ok ? await res.json() : null
    }
    catch{ store.set('alive', false);
        return nulls
    }
}