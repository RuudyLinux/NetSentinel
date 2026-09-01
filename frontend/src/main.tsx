import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import { AuditDetailPage } from "./features/audits/AuditDetailPage";
import { AuditListPage } from "./features/audits/AuditListPage";
import { LoginPage } from "./features/auth/LoginPage";
import { UploadPage } from "./features/ingestion/UploadPage";
import "./index.css";
import { AuthProvider, RequireAuth } from "./lib/auth";

const queryClient = new QueryClient();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route
              element={
                <RequireAuth>
                  <AppShell />
                </RequireAuth>
              }
            >
              <Route index element={<AuditListPage />} />
              <Route path="upload" element={<UploadPage />} />
              <Route path="audits" element={<AuditListPage />} />
              <Route path="audits/:id" element={<AuditDetailPage />} />
            </Route>
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
