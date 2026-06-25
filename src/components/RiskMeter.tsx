import { cn } from "@/lib/utils";

interface Props {
  score: number;
  classification: "safe" | "suspicious" | "phishing";
  size?: "sm" | "lg";
}

const COLORS = {
  safe: "var(--success)",
  suspicious: "var(--warning)",
  phishing: "var(--destructive)",
} as const;

const LABELS = {
  safe: "Safe",
  suspicious: "Suspicious",
  phishing: "High Risk Phishing",
} as const;

export function RiskMeter({ score, classification, size = "lg" }: Props) {
  const color = COLORS[classification];
  return (
    <div className={cn("w-full", size === "sm" && "max-w-sm")}>
      <div className="flex items-end justify-between mb-2">
        <div>
          <div className="text-xs uppercase tracking-widest text-muted-foreground">Risk Score</div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-bold tabular-nums" style={{ color }}>
              {score}
            </span>
            <span className="text-muted-foreground">/ 100</span>
          </div>
        </div>
        <span
          className="px-3 py-1 rounded-full text-xs font-semibold uppercase tracking-wider"
          style={{ background: `color-mix(in oklab, ${color} 20%, transparent)`, color }}
        >
          {LABELS[classification]}
        </span>
      </div>
      <div className="h-3 w-full rounded-full bg-muted overflow-hidden relative">
        <div
          className="h-full transition-all duration-700 ease-out rounded-full"
          style={{
            width: `${score}%`,
            background: `linear-gradient(90deg, var(--success) 0%, var(--warning) 50%, var(--destructive) 100%)`,
            maskImage: `linear-gradient(90deg, black ${score}%, transparent ${score}%)`,
          }}
        />
        <div
          className="absolute inset-y-0 left-0 transition-all duration-700 ease-out"
          style={{
            width: `${score}%`,
            background: `linear-gradient(90deg, var(--success) 0%, var(--warning) 50%, var(--destructive) 100%)`,
            opacity: 0.9,
          }}
        />
      </div>
      <div className="flex justify-between text-[10px] uppercase tracking-widest text-muted-foreground mt-1">
        <span>0 Safe</span>
        <span>30</span>
        <span>60</span>
        <span>100 Critical</span>
      </div>
    </div>
  );
}