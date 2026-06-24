import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import AnalyzePage from "./pages/AnalyzePage";
import HistoryPage from "./pages/HistoryPage";
import AnalysisDetailPage from "./pages/AnalysisDetailPage";
import TrainingPage from "./pages/TrainingPage";
import SampleDetailPage from "./pages/SampleDetailPage";
import QuizPage from "./pages/QuizPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<AnalyzePage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/analysis/:id" element={<AnalysisDetailPage />} />
          <Route path="/training" element={<TrainingPage />} />
          <Route path="/training/quiz" element={<QuizPage />} />
          <Route path="/training/:id" element={<SampleDetailPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
