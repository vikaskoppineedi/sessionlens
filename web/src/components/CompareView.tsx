import { useEffect, useState } from 'react';
import { api } from '../api';
import type { Comparison, SessionInfo } from '../types';

interface Props {
  current: string;
  sessions: SessionInfo[];
  onClose: () => void;
}

function Lists({ title, data }: { title: string; data: { onlyA: string[]; onlyB: string[]; both: string[] } }) {
  return (
    <>
      <h3>{title}</h3>
      <div className="compare-cols">
        {(['onlyA', 'both', 'onlyB'] as const).map((key) => (
          <div key={key}>
            <h4>
              {key === 'onlyA' ? 'Only in this session' : key === 'onlyB' ? 'Only in the other' : 'In both'} ({data[key].length})
            </h4>
            <ul>
              {data[key].map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </>
  );
}

export function CompareView({ current, sessions, onClose }: Props) {
  const others = sessions.filter((s) => s.id !== current);
  const [other, setOther] = useState(others[0]?.id ?? '');
  const [result, setResult] = useState<Comparison | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!other) return;
    api.compare(current, other).then(setResult, (e: Error) => setError(e.message));
  }, [current, other]);

  return (
    <aside className="drawer wide">
      <button className="close" onClick={onClose} aria-label="close">
        ✕
      </button>
      <h2>Compare sessions</h2>
      {others.length === 0 ? (
        <p className="muted">Capture another session first (e.g. the same login on another day).</p>
      ) : (
        <>
          <label>
            {current} vs{' '}
            <select value={other} onChange={(e) => setOther(e.target.value)}>
              {others.map((s) => (
                <option key={s.id}>{s.id}</option>
              ))}
            </select>
          </label>
          {error ? <p className="error">{error}</p> : null}
          {result ? (
            <>
              <Lists title="Cookies" data={result.cookies} />
              <Lists title="Endpoints (method host path)" data={result.endpoints} />
              <p>
                Blocked cookies: {result.blocked.a} vs {result.blocked.b}
              </p>
            </>
          ) : null}
        </>
      )}
    </aside>
  );
}
