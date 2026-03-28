import { Outlet, Link, useLocation } from "react-router-dom";
import { Fish } from "lucide-react";
import { motion } from "motion/react";

export default function Layout() {
  const location = useLocation();

  return (
    <div className="min-h-svh flex flex-col">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-border/50 backdrop-blur-xl bg-background/70">
        <div className="max-w-5xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2.5 group">
            <div className="relative">
              <Fish className="w-7 h-7 text-primary transition-colors group-hover:text-accent" />
              <div className="absolute inset-0 blur-lg bg-primary/30 group-hover:bg-accent/30 transition-colors" />
            </div>
            <span className="font-heading text-lg font-bold tracking-tight text-foreground">
              Tiny<span className="text-primary">Phish</span>
            </span>
          </Link>
          <nav className="flex items-center gap-1">
            <Link
              to="/"
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                location.pathname === "/"
                  ? "text-primary bg-primary/10"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Scan
            </Link>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 relative">
        <motion.div
          key={location.pathname}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -12 }}
          transition={{ duration: 0.3, ease: "easeOut" }}
        >
          <Outlet />
        </motion.div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border/50 py-6">
        <div className="max-w-5xl mx-auto px-6 flex items-center justify-between text-xs text-muted-foreground">
          <span>
            Powered by{" "}
            <span className="text-primary font-medium">TinyFish</span>
          </span>
          <span className="font-mono opacity-60">v1.0.0</span>
        </div>
      </footer>
    </div>
  );
}
