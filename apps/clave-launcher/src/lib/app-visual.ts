import {
  AppWindow,
  Briefcase,
  Chrome,
  FileText,
  Folder,
  Globe,
  GraduationCap,
  type LucideIcon,
  Mail,
  Presentation,
  Sheet,
  Slack,
  Users,
} from "lucide-react";

// Map an app to a brand-coloured tile + glyph. Keyword-matched off the label so it scales to any
// allow-listed app; unknown apps fall back to a neutral window glyph. Shared by the full and
// compact views so both render apps identically.
export function visualFor(label: string): { Icon: LucideIcon; bg: string } {
  const l = label.toLowerCase();
  if (l.includes("chrome")) return { Icon: Chrome, bg: "bg-[#1a73e8]" };
  if (l.includes("excel")) return { Icon: Sheet, bg: "bg-[#1d8f4e]" };
  if (l.includes("word")) return { Icon: FileText, bg: "bg-[#2b579a]" };
  if (l.includes("outlook")) return { Icon: Mail, bg: "bg-[#0f6cbd]" };
  if (l.includes("file")) return { Icon: Folder, bg: "bg-[#eaa400]" };
  if (l.includes("point")) return { Icon: Presentation, bg: "bg-[#c43e1c]" };
  if (l.includes("edge")) return { Icon: Globe, bg: "bg-[#0e8c8c]" };
  if (l.includes("academy")) return { Icon: GraduationCap, bg: "bg-[#4f46e5]" };
  if (l.includes("acrobat") || l.includes("adobe") || l.includes("pdf"))
    return { Icon: FileText, bg: "bg-[#e3001b]" };
  if (l.includes("work")) return { Icon: Briefcase, bg: "bg-[#e23b50]" };
  if (l.includes("teams")) return { Icon: Users, bg: "bg-[#5b5fc7]" };
  if (l.includes("slack")) return { Icon: Slack, bg: "bg-[#611f69]" };
  return { Icon: AppWindow, bg: "bg-zinc-500" };
}
