import { sleep } from "$utils/index.js";
import { Log } from "$utils/logger.js";

Log.debug("hello");

let currentUuid = null;
let serverDown = false;
async function hotreload() {
  while (true) {
    await sleep(1000); // sleep for 2 seconds

    try {
      const res = await fetch("/hot-reload");
      const json = await res.json();
      const uuid = json.uuid;
      // const debug = json?.debug ?? false;

      currentUuid ||= uuid;

      serverDown = false;

      if (currentUuid !== uuid) {
        location.reload();
      }
    } catch (_err) {
      if (!serverDown) {
        console.warn(`Server Down`);
      }
      serverDown = true;
    }
  }
}

hotreload();
