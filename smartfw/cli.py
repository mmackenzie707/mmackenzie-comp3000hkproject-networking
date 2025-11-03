#Execution of full pipeline: Capture, Feautres, Model, Firewall, and API

import logging, queue, signal, threading
from smartfw import CaptureEngine, AnomalyModel, Firewall, build_app, THREASHOLD


logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
log = logging.getLogger("smartfw.cli")


def main():
    q: "queue.Queue[smartfw.Flow]" = queue.Queue(maxsize=10_000)
    model = AnomalyModel(); model.load_or_create()
    fw = Firewall(); fw.start()
    capture = CaptureEngine(q); capture.start()


    def worker():
        while True:
            flow = q.get()
            vec = flow_to_vector(flow)
            if vec is None:
                continue
            score = model.score(vec)
            if score < THREASHOLD:
                bad_ip = flow.five_tuple[0] if flow.dir_list[0] == 1 else flow.five_tuple [3]
                fw.block(bad_ip)

    threading.Thread(target=worker, daemon=True).start()


    #Nightly machine learning retrain
    def retrain():
        import time
        while True:
            time.sleep(86_400)
            model.maybe_retrain()
    threading.Thread(target=retrain, daemon=True).start()


    #API connection
    app = build_app(fw, model)
    threading.Thread(target=lambda: app.run("0.0.0.0", 5000), daemon=True).start()


    #Shutdown
    def _sig(*_):
        capture.stop()
        import sys; sys.exit(0)
    signal.signal(signal.SIGINT, _sig)

    log.info("SmartFW modular ready")
    threading.Event().wait()

if __name__ == "__main__":
    main()