import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Layout } from "./components/Layout";
import { OverviewPage } from "./pages/OverviewPage";
import { PolicyPage } from "./pages/PolicyPage";
import { MetricsPage } from "./pages/MetricsPage";
import { AuditPage } from "./pages/AuditPage";
import { DoctorPage } from "./pages/DoctorPage";
import { ProfilesPage } from "./pages/ProfilesPage";
import { CachePage } from "./pages/CachePage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      refetchOnWindowFocus: false,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<OverviewPage />} />
            <Route path="profiles" element={<ProfilesPage />} />
            <Route path="policy" element={<PolicyPage />} />
            <Route path="metrics" element={<MetricsPage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="doctor" element={<DoctorPage />} />
            <Route path="cache" element={<CachePage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
