import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AnimatePresence } from "motion/react";
import { Toaster } from "@/components/ui/sonner";
import Layout from "@/components/Layout";
import HomePage from "@/pages/HomePage";
import ResultsPage from "@/pages/ResultsPage";

function App() {
  return (
    <BrowserRouter>
      <AnimatePresence mode="wait">
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<HomePage />} />
            <Route path="/results" element={<ResultsPage />} />
          </Route>
        </Routes>
      </AnimatePresence>
      <Toaster position="bottom-right" richColors />
    </BrowserRouter>
  );
}

export default App;
