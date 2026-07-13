import { useEffect, useState } from "react";
import { CompactView } from "@/components/compact-view";
import { FullView } from "@/components/full-view";

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
