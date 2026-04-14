import { useCallback, useState } from 'react';
import { consumeAiStream } from '../api/client';

/**
 * Hook for SSE AI streaming responses.
 */
export function useAiStream() {
  const [content, setContent] = useState('');
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState('');

  const stream = useCallback(async (path, body) => {
    setContent('');
    setError('');
    setStreaming(true);
    let accumulated = '';

    try {
      await consumeAiStream(path, body, {
        onDelta: (chunk) => {
          accumulated += chunk;
          setContent(accumulated);
        },
        onFinal: (data) => {
          if (data?.analysis) setContent(data.analysis);
          else if (data?.remediation) setContent(data.remediation);
          else if (data?.summary) setContent(data.summary);
          else if (data?.explanation) setContent(data.explanation);
        },
        onError: (data) => {
          const msg = typeof data === 'string' ? data
            : data?.message || 'AI service temporarily unavailable.';
          setError(msg);
        },
      });
    } catch (e) {
      setError(e.message || 'AI request failed.');
    } finally {
      setStreaming(false);
    }
  }, []);

  const reset = useCallback(() => {
    setContent('');
    setError('');
    setStreaming(false);
  }, []);

  return { content, streaming, error, stream, reset };
}
