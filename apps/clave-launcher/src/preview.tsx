import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { FullView } from "./components/full-view";
import "./index.css";

const APPS = [
  { id: "chrome-work", label: "Google Chrome" },
  { id: "excel-work", label: "Excel" },
  { id: "word-work", label: "Word" },
  { id: "outlook-work", label: "Outlook" },
  { id: "files-work", label: "Files" },
  { id: "powerpoint-work", label: "PowerPoint" },
  { id: "edge-work", label: "Edge" },
  { id: "acrobat-work", label: "Adobe Acrobat" },
  { id: "teams-work", label: "Teams" },
  { id: "slack-work", label: "Slack" },
  { id: "vscode-work", label: "Visual Studio Code" },
  { id: "cursor-work", label: "Cursor" },
];

const POSTURE = [
  { capability: "App supervision", status: "development-only" },
  { capability: "Split-tunnel routing", status: "development-only" },
  { capability: "Encrypted volume mount", status: "unavailable" },
  { capability: "Exec authorization", status: "unavailable" },
  { capability: "Filesystem redirection", status: "unavailable" },
  { capability: "Audit spool", status: "enforced" },
];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(window as any).__TAURI_INTERNALS__ = {
  invoke: async (cmd: string) => {
    if (cmd === "list_apps") return APPS;
    if (cmd === "enforcement") return POSTURE;
    if (cmd === "launch_app") return 4242 + Math.floor(Math.random() * 1000);
    if (cmd === "launch_spec")
      return {
        executable: "/Applications/Demo.app",
        args: ["--user-data-dir=/Volumes/ClaveDisk/profiles/demo"],
        env: [["HOME", "/Volumes/ClaveDisk/profiles/demo"]],
        namespace_prefix: null,
      };
    return null;
  },
};

const view = new URLSearchParams(location.search).get("view");
const node =
  view === "collapsed" ? (
    <FullView initialCollapsed />
  ) : view === "edit" ? (
    <FullView initialEditing />
  ) : (
    <App />
  );

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>{node}</React.StrictMode>,
);
