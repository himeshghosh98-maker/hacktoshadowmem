import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";
import { Header } from "@/components/Header";
import { DensityProvider } from "@/context/DensityContext";
import { ConnectionProvider } from "@/context/ConnectionContext";
import { NotificationsProvider } from "@/context/NotificationsContext";
import { ConnectionBanner } from "@/components/ConnectionBanner";

export const metadata: Metadata = {
  title: "ShadowMem — Cyber Defense Operations Center",
  description: "Automated volatile memory forensics and fileless malware detection.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="bg-background text-textBright font-sans antialiased overflow-hidden">
        <ConnectionProvider>
          <DensityProvider>
            <NotificationsProvider>
              <div className="flex h-screen w-screen overflow-hidden">
                {/* Persistent Left Sidebar */}
                <Sidebar />

                {/* Main App Workspace */}
                <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden bg-background">
                  <Header />
                  <ConnectionBanner />
                  <main className="flex-1 overflow-y-auto p-6 space-y-6">
                    {children}
                  </main>
                </div>
              </div>
            </NotificationsProvider>
          </DensityProvider>
        </ConnectionProvider>
      </body>
    </html>
  );
}
