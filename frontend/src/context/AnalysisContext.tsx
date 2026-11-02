import {
  createContext,
  useCallback,
  useContext,
  useState,
  type ReactNode,
} from "react";

import {
  analyzeFirewall,
  type AnalysisResponse,
} from "../services/firewallApi";

interface AnalysisContextValue {
  analysis: AnalysisResponse | null;
  loading: boolean;
  error: string | null;
  filename: string | null;
  analyze: (file: File) => Promise<boolean>;
  clear: () => void;
}

const AnalysisContext = createContext<
  AnalysisContextValue | undefined
>(undefined);

export function AnalysisProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [analysis, setAnalysis] =
    useState<AnalysisResponse | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filename, setFilename] = useState<string | null>(
    null,
  );

  const analyze = useCallback(
    async (file: File): Promise<boolean> => {
      setLoading(true);
      setError(null);

      try {
        const result = await analyzeFirewall(file);

        setAnalysis(result);
        setFilename(file.name);

        return true;
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "An unexpected error occurred.",
        );

        return false;
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  const clear = useCallback(() => {
    setAnalysis(null);
    setFilename(null);
    setError(null);
  }, []);

  return (
    <AnalysisContext.Provider
      value={{
        analysis,
        loading,
        error,
        filename,
        analyze,
        clear,
      }}
    >
      {children}
    </AnalysisContext.Provider>
  );
}

export function useAnalysis(): AnalysisContextValue {
  const context = useContext(AnalysisContext);

  if (!context) {
    throw new Error(
      "useAnalysis must be used inside AnalysisProvider",
    );
  }

  return context;
}