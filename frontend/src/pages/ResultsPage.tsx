import { useLocation, useNavigate, Navigate } from "react-router-dom";
import { motion } from "motion/react";
import { ArrowLeft, Sparkles, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import ConfidenceGauge from "@/components/ConfidenceGauge";
import RiskCard from "@/components/RiskCard";
import MetadataTable from "@/components/MetadataTable";
import type { AnalysisResult } from "@/lib/types";

export default function ResultsPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const result = location.state as AnalysisResult | null;

  if (!result) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="max-w-5xl mx-auto px-6 py-10 md:py-16">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="mb-10"
      >
        <Button
          variant="ghost"
          size="sm"
          onClick={() => navigate("/")}
          className="text-muted-foreground hover:text-foreground mb-4 -ml-2 cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4 mr-1.5" />
          Back
        </Button>
        <h1 className="font-heading text-2xl md:text-3xl font-bold text-foreground mb-2">
          Analysis Results
        </h1>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <ExternalLink className="w-3.5 h-3.5" />
          <span className="font-mono text-xs truncate max-w-md">
            {result.url}
          </span>
        </div>
      </motion.div>

      {/* Score + Metadata grid */}
      <div className="grid grid-cols-1 md:grid-cols-[auto_1fr] gap-8 md:gap-12 mb-10">
        <ConfidenceGauge score={result.confidenceScore} />
        <MetadataTable metadata={result.metadata} />
      </div>

      <Separator className="bg-border/40 my-10" />

      {/* AI Summary */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.5 }}
        className="bg-card/60 backdrop-blur-sm rounded-lg border border-border/60 border-l-[3px] border-l-cyan p-6 mb-10"
      >
        <div className="flex items-center gap-2 mb-4">
          <Sparkles className="w-4 h-4 text-cyan" />
          <h3 className="font-heading text-sm font-bold text-foreground">
            AI Analysis
          </h3>
        </div>
        <p className="text-foreground/85 text-sm leading-relaxed">
          {result.aiSummary}
        </p>
      </motion.div>

      {/* Risk Breakdown */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3 }}
      >
        <h2 className="font-heading text-lg font-bold text-foreground mb-5">
          Risk Breakdown
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {result.riskCategories.map((cat, i) => (
            <RiskCard key={cat.name} category={cat} index={i} />
          ))}
        </div>
      </motion.div>

      <Separator className="bg-border/40 my-10" />

      {/* CTA */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.8 }}
        className="text-center"
      >
        <Button
          onClick={() => navigate("/")}
          className="bg-primary hover:bg-primary/90 text-primary-foreground cursor-pointer transition-all hover:shadow-[0_0_24px_-4px] hover:shadow-primary/40"
        >
          Scan Another Link
        </Button>
        <p className="text-muted-foreground/50 text-xs mt-3 font-mono">
          analyzed at{" "}
          {new Date(result.analyzedAt).toLocaleString()}
        </p>
      </motion.div>
    </div>
  );
}
