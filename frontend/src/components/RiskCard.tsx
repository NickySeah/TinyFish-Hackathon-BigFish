import { motion } from "motion/react";
import { Badge } from "@/components/ui/badge";
import {
  Fish,
  AlertTriangle,
  Globe,
  Lock,
  Clock,
  ExternalLink,
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

const LEVEL_STYLES = {
  safe: {
    badge: "bg-safe/15 text-safe border-safe/30 hover:bg-safe/15",
    border: "border-l-safe",
    text: "Safe",
  },
  warning: {
    badge: "bg-warning/15 text-warning border-warning/30 hover:bg-warning/15",
    border: "border-l-warning",
    text: "Warning",
  },
  danger: {
    badge: "bg-danger/15 text-danger border-danger/30 hover:bg-danger/15",
    border: "border-l-danger",
    text: "Danger",
  },
};

interface RiskCardProps {
  category: RiskCategory;
  index: number;
}

export default function RiskCard({ category, index }: RiskCardProps) {
  const Icon = CATEGORY_ICONS[category.name] || AlertTriangle;
  const style = LEVEL_STYLES[category.level];

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: 0.1 * index + 0.3 }}
      className={`group bg-card/60 backdrop-blur-sm rounded-lg border border-border/60 border-l-[3px] ${style.border} p-5 transition-all hover:bg-card/80 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-primary/5`}
    >
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2.5">
          <Icon className="w-4 h-4 text-muted-foreground shrink-0" />
          <h3 className="font-heading text-sm font-bold text-foreground">
            {category.name}
          </h3>
        </div>
        <Badge
          variant="outline"
          className={`text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 ${style.badge}`}
        >
          {style.text}
        </Badge>
      </div>
      <p className="text-muted-foreground text-sm leading-relaxed">
        {category.description}
      </p>
    </motion.div>
  );
}
