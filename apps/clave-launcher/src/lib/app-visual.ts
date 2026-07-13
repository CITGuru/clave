import { AppWindow, Briefcase, Folder, GraduationCap, type LucideIcon } from "lucide-react";

const brandUrls = import.meta.glob<string>("../assets/app-icons/*.svg", {
  eager: true,
  query: "?url",
  import: "default",
});

function brandUrl(slug: string): string | undefined {
  return brandUrls[`../assets/app-icons/${slug}.svg`];
}

function slugFor(label: string): string | undefined {
  const l = label.toLowerCase();
  if (l.includes("cursor")) return "cursor";
  if (l.includes("code") || l.includes("visual studio"))
    return "visual-studio-code";
  if (l.includes("chrome")) return "google-chrome";
  if (l.includes("excel")) return "microsoft-excel";
  if (l.includes("word")) return "microsoft-word";
  if (l.includes("outlook")) return "microsoft-outlook";
  if (l.includes("point")) return "microsoft-powerpoint";
  if (l.includes("edge")) return "microsoft-edge";
  if (l.includes("teams")) return "microsoft-teams";
  if (l.includes("slack")) return "slack";
  if (l.includes("acrobat") || l.includes("adobe") || l.includes("pdf"))
    return "acrobat-reader";
  return undefined;
}

export type AppVisual = {
  src?: string;
  Icon: LucideIcon;
  bg: string;
};

export function visualFor(label: string): AppVisual {
  const slug = slugFor(label);
  const src = slug ? brandUrl(slug) : undefined;
  if (src) return { src, Icon: AppWindow, bg: "bg-white" };

  const l = label.toLowerCase();
  if (l.includes("file")) return { Icon: Folder, bg: "bg-[#eaa400]" };
  if (l.includes("academy")) return { Icon: GraduationCap, bg: "bg-[#4f46e5]" };
  if (l.includes("work")) return { Icon: Briefcase, bg: "bg-[#e23b50]" };
  return { Icon: AppWindow, bg: "bg-zinc-500" };
}
