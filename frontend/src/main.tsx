import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import { ToastProvider } from "./components/ui/Toast";
import { AuditLogsPage } from "./features/admin/AuditLogsPage";
import { DiagnosticsPage } from "./features/admin/DiagnosticsPage";
import { RolesPage } from "./features/admin/RolesPage";
import { UsersPage } from "./features/admin/UsersPage";
import { AiInsightsPage } from "./features/ai/AiInsightsPage";
import { ForgotPasswordPage } from "./features/auth/ForgotPasswordPage";
import { LoginPage } from "./features/auth/LoginPage";
import { SessionExpiredPage } from "./features/auth/SessionExpiredPage";
import { AuditDetailPage } from "./features/audits/AuditDetailPage";
import { AuditListPage } from "./features/audits/AuditListPage";
import { ComplianceDetailPage } from "./features/compliance/ComplianceDetailPage";
import { CompliancePage } from "./features/compliance/CompliancePage";
import { DashboardPage } from "./features/dashboard/DashboardPage";
import { DeviceDetailPage } from "./features/devices/DeviceDetailPage";
import { DevicesPage } from "./features/devices/DevicesPage";
import { DiscoveryPage } from "./features/discovery/DiscoveryPage";
import { Forbidden403Page } from "./features/errors/Forbidden403Page";
import { NotFound404Page } from "./features/errors/NotFound404Page";
import { FindingDetailPage } from "./features/findings/FindingDetailPage";
import { FindingsPage } from "./features/findings/FindingsPage";
import { ConfigurationsPage } from "./features/ingestion/ConfigurationsPage";
import { ReportsPage } from "./features/reports/ReportsPage";
import "./index.css";
import { AuthProvider, RequireAuth } from "./lib/auth";
import { ApiError } from "./lib/api";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // React Query's default retries every error, including 4xx responses that will
      // never succeed on retry (404 Not Found, 403 Forbidden, ...). That wastes ~7s of
      // exponential backoff before an already-correct isError branch gets to render,
      // making pages that ARE handling the error look stuck. Only retry errors a retry
      // could plausibly fix — network failures and 5xx — not client errors.
      retry: (failureCount, error) =>
        failureCount < 3 && !(error instanceof ApiError && error.status >= 400 && error.status < 500),
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <ToastProvider>
            <Routes>
              <Route path="/login" element={<Navigate to="/auth/login" replace />} />
              <Route path="/auth/login" element={<LoginPage />} />
              <Route path="/auth/forgot-password" element={<ForgotPasswordPage />} />
              <Route path="/auth/session-expired" element={<SessionExpiredPage />} />
              <Route path="/403" element={<Forbidden403Page />} />
              <Route
                element={
                  <RequireAuth>
                    <AppShell />
                  </RequireAuth>
                }
              >
                <Route index element={<DashboardPage />} />
                <Route path="devices" element={<DevicesPage />} />
                <Route path="devices/:id" element={<DeviceDetailPage />} />
                <Route path="discovery" element={<DiscoveryPage />} />
                <Route path="configurations" element={<ConfigurationsPage />} />
                <Route path="audits" element={<AuditListPage />} />
                <Route path="audits/:id" element={<AuditDetailPage />} />
                <Route path="findings" element={<FindingsPage />} />
                <Route path="findings/:id" element={<FindingDetailPage />} />
                <Route path="compliance" element={<CompliancePage />} />
                <Route path="compliance/:framework" element={<ComplianceDetailPage />} />
                <Route path="ai-insights" element={<AiInsightsPage />} />
                <Route path="reports" element={<ReportsPage />} />
                <Route path="admin/users" element={<UsersPage />} />
                <Route path="admin/roles" element={<RolesPage />} />
                <Route path="admin/audit-logs" element={<AuditLogsPage />} />
                <Route path="admin/diagnostics" element={<DiagnosticsPage />} />
              </Route>
              <Route path="*" element={<NotFound404Page />} />
            </Routes>
          </ToastProvider>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
