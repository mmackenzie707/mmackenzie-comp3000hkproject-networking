import { initBlockedList } from "./components/blockedlist";
import { initSparkline } from "./components/sparkline";
import { initThreshold } from "./components/threshold";
import { initWhitelist } from "./components/whitelist";
import { initHeader } from "./components/header";

//Complete all in one initialization
initWhitelist();
initBlockedList();
initHeader();
initThreshold();
initSparkline();

//Polling Loop
async function poll() {
    const data = await api.get('/');
    store.set('alive',!!data);
    if(data) store.set('blocked', new Set(data.blocked||[]));
}
poll(); setInterval(poll,2000);