import { useEffect, useState } from "react";
import { CompactView } from "@/components/compact-view";
import { FullView } from "@/components/full-view";

// Below this content width the window shows the compact quick-launch panel (the "minimized" view);
// at or above it, the full two-pane launcher. Resize the window across the threshold to switch.
const COMPACT_MAX = 640;

export default function App() {
  const [narrow, setNarrow] = useState(() => window.innerWidth < COMPACT_MAX);

  useEffect(() => {
    const onResize = () => setNarrow(window.innerWidth < COMPACT_MAX);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  return narrow ? <CompactView /> : <FullView />;
}
