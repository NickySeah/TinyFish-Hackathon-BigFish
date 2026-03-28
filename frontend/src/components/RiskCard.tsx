import { motion } from "motion/react";
import {
  AlertTriangle,
  Globe,
  Lock,
  CreditCard,
  Users,
  Code,
  Link2,
  Bug,
  ShieldAlert,
} from "lucide-react";
import type { PhishingIndicator } from "@/lib/types";

const CATEGORY_ICONS: Record<string, React.ElementType> = {
  "URL/Domain Spoofing": Link2,
  "Urgency/Fear Tactics": AlertTriangle,
  "Credential Harvesting": Lock,
  "Social Engineering": Users,
  "Technical Indicators": Code,
  "Financial/Payment Red Flags": CreditCard,
  "Brand Impersonation": Globe,
  "Malware/Drive-by Downloads": Bug,
};

interface IndicatorCardProps {
  indicator: PhishingIndicator;
  index: number;
}

export default function RiskCard({ indicator, index }: IndicatorCardProps) {
  const Icon = CATEGORY_ICONS[indicator.category] || ShieldAlert;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.08 * index + 0.3, ease: "easeOut" }}
      className="group relative bg-card/50 backdrop-blur-sm rounded-lg border border-border/50 overflow-hidden transition-all duration-300 hover:-translate-y-1 hover:shadow-xl shadow-danger/10 hover:border-border/80"
    >
      {/* Top accent bar */}
      <div className="h-0.5 bg-danger opacity-60" />

      <div className="p-5">
        {/* Icon + Status row */}
        <div className="flex items-start justify-between mb-4">
          <div className="p-2 rounded-md bg-danger/5 border border-border/30">
            <Icon className="w-4 h-4 text-danger" />
          </div>
          <div className="flex items-center gap-1.5">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-danger animate-pulse" />
            <span className="font-mono text-[10px] uppercase tracking-widest text-danger">
              Indicator
            </span>
          </div>
        </div>

        {/* Title */}
        <h3 className="font-heading text-sm font-bold text-foreground mb-2 tracking-tight">
          {indicator.category}
        </h3>

        {/* Description */}
        <p className="text-muted-foreground text-xs leading-relaxed line-clamp-3">
          {indicator.detail}
        </p>
      </div>
    </motion.div>
  );
}
