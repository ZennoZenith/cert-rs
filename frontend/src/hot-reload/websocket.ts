async function liveReload(hard: boolean) {
  const wsProtocol = location.protocol === "https:" ? "wss:" : "ws:";
  const addr = `${wsProtocol}//${location.host}/live-server-ws`;
  const sleep = (x: number) => new Promise((r) => setTimeout(r, x));

  const preload = async (url: string, requireSuccess: boolean) => {
    const resp = await fetch(url, { cache: "reload" }); // reset cache
    if (requireSuccess && (!resp.ok || resp.status !== 200)) {
      throw new Error();
    }
  };

  /** Reset cache in link.href and strip scripts */
  const preloadNode = (n: HTMLElement | ChildNode, ps: Promise<void>[]) => {
    if (n instanceof HTMLScriptElement && n.tagName === "SCRIPT" && n.src) {
      ps.push(preload(n.src, false));
      return;
    }

    if (n instanceof HTMLLinkElement && n.tagName === "LINK" && n.href) {
      ps.push(preload(n.href, false));
      return;
    }

    let c = n.firstChild;
    while (c) {
      const nc = c.nextSibling;
      preloadNode(c, ps);
      c = nc;
    }
  };

  let reloading = false; // if the page is currently being reloaded
  let scheduled = false; // if another reload is scheduled while the page is being reloaded

  async function reload() {
    if (hard) {
      location.reload();
      return;
    }

    // schedule the reload for later if it's already reloading
    if (reloading) {
      scheduled = true;
      return;
    }
    let ifr: any; // HtmlIFrameElement or null
    reloading = true;

    while (true) {
      scheduled = false;
      const url = location.origin + location.pathname;

      const promises: Promise<void>[] = [];
      preloadNode(document.head, promises);
      preloadNode(document.body, promises);

      await Promise.allSettled(promises);
      try {
        await new Promise((resolve) => {
          ifr = document.createElement("iframe");
          ifr.src = `${url}`;
          ifr.style.display = "none";
          ifr.onload = resolve;
          document.body.appendChild(ifr);
        });
      } catch {}

      // reload only if the iframe loaded successfully
      // with the reload payload. If the reload payload
      // is absent, it probably means the server responded
      // with a 404 page
      const meta = (
        ifr as HTMLIFrameElement
      )?.contentDocument?.head.querySelector(
        'meta[name="live-server"]',
      ) as HTMLMetaElement;

      if (
        meta &&
        meta.tagName === "META" &&
        meta.name === "live-server" &&
        meta.content === "reload"
      ) {
        // do reload if there's no further scheduled reload
        // otherwise, let the next scheduled reload do the job
        if (!scheduled) {
          reloading = false;
          document.head.replaceWith(ifr.contentDocument.head);
          document.body.replaceWith(ifr.contentDocument.body);
          ifr.remove();
          console.log("[Live Server] Reloaded");
        }
        return;
      }

      if (ifr) {
        ifr.remove();
      }
      // wait for some time before trying again
      await sleep(500);
    }
  }

  let connectedInterrupted = false; // track if it's the first connection or a reconnection
  while (true) {
    try {
      await new Promise((resolve) => {
        const ws = new WebSocket(addr);
        ws.onopen = () => {
          console.log("[Live Server] Connection Established");
          // on reconnection, refresh the page
          if (connectedInterrupted) {
            reload();
          }
        };
        ws.onmessage = reload;
        ws.onerror = () => ws.close();
        ws.onclose = resolve;
      });
    } catch {}
    connectedInterrupted = true;
    await sleep(3000);
    console.log("[Live Server] Reconnecting...");
  }
}
