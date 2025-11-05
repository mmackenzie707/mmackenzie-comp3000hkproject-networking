const BASE = 'http://localhost:5000'
export const api = {
    async get(path){ return useCallback('GET', path); },
}