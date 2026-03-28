import { motion } from "motion/react";
import {
  Fish,
  AlertTriangle,
  Globe,
  Lock,
  Clock,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
} from "lucide-react";
import type { RiskCategory } from "@/lib/types";

const CATEGORY_ICONS: Record<string, React.ElementType> = {
  "Domain Registration": Clock,
  "SSL Certificate": Lock,
  "Page Content": Globe,
  "URL Structure": ExternalLink,
  "Redirect Chain": ExternalLink,
  "External Resources": Fish,
};

const LEVEL_CONFIG = {
  safe: {
    label: "Clear",
    StatusIcon: ShieldCheck,
    glow: "shadow-safe/8",
    accent: "text-safe",
    bg: "bg-safe/5",
    dot: "bg-safe",
    bar: "bg-safe",
  },
  warning: {
    label: "Suspicious",
    StatusIcon: ShieldAlert,
    glow: "shadow-warning/8",
    accent: "text-warning",
    bg: "bg-warning/5",
    dot: "bg-warning",
    bar: "bg-warning",
  },
  danger: {
    label: "Threat",
    StatusIcon: ShieldX,
    glow: "shadow-danger/10",
    accent: "text-danger",
    bg: "bg-danger/5",
    dot: "bg-danger",
    bar: "bg-danger",
  },
};

interface RiskCardProps {
  category: RiskCategory;
  index: number;
}

export default function RiskCard({ category, index }: RiskCardProps) {
  const Icon = CATEGORY_ICONS[category.name] || AlertTriangle;
  const cfg = LEVEL_CONFIG[category.level];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.08 * index + 0.3, ease: "easeOut" }}
      className={`group relative bg-card/50 backdrop-blur-sm rounded-lg border border-border/50 overflow-hidden transition-all duration-300 hover:-translate-y-1 hover:shadow-xl ${cfg.glow} hover:border-border/80`}
    >
      {/* Top accent bar */}
      <div className={`h-0.5 ${cfg.bar} opacity-60`} />

      <div className="p-5">
        {/* Icon + Status row */}
        <div className="flex items-start justify-between mb-4">
          <div className={`p-2 rounded-md ${cfg.bg} border border-border/30`}>
            <Icon className={`w-4 h-4 ${cfg.accent}`} />
          </div>
          <div className="flex items-center gap-1.5">
            <span className={`inline-block w-1.5 h-1.5 rounded-full ${cfg.dot} animate-pulse`} />
            <span className={`font-mono text-[10px] uppercase tracking-widest ${cfg.accent}`}>
              {cfg.label}
            </span>
          </div>
        </div>

        {/* Title */}
        <h3 className="font-heading text-sm font-bold text-foreground mb-2 tracking-tight">
          {category.name}
        </h3>

        {/* Description */}
        <p className="text-muted-foreground text-xs leading-relaxed line-clamp-3">
          {category.description}
        </p>
      </div>
    </motion.div>
  );
}
