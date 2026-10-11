import { useEffect, useState } from 'react';
import { api, subscribe } from './api';
import icon from './assets/icon.png';
import { CompareView } from './components/CompareView';
import { Drawer } from './components/Drawer';
import { Matrix } from './components/Matrix';
import { StepStrip } from './components/StepStrip';
import type { Filters, Selection } from './state';
import type { Model, SessionInfo } from './types';

function StatusPills({ model }: { model: Model }) {
  const { status } = model;
  const pill = (ok: boolean | null, label: string, title: string) => (
    <span className={`pill ${ok === null ? 'idle' : ok ? 'ok' : 'bad'}`} title={title}>
      {label}
    </span>
  );
  return (
    <div className="pills">
      {model.live ? pill(true, '● LIVE', 'capture running') : pill(null, 'saved session', 'capture finished')}
      {pill(model.live ? (status.components.extension?.ok ?? false) : null, `extension ${status.extensionEvents}`, 'events from the Chrome extension')}
      {pill(model.live ? (status.components.tshark?.ok ?? false) : null, `wire ${status.wireMessages}`, 'decrypted HTTP messages from tshark')}
      {pill(null, `disk ${status.diskSnapshots}`, 'cookie database snapshots')}
    </div>
  );
}

const DEFAULT_FILTERS: Filters = { changedOnly: false, hideTrackers: true, search: '' };

/** Everything for one session; keyed by session id so switching sessions starts fresh. */
function SessionView({ session, sessions, onError }: { session: string; sessions: SessionInfo[]; onError: (msg: string) => void }) {
  const [model, setModel] = useState<Model | null>(null);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [selectedStep, setSelectedStep] = useState<number | null>(null);
  const [reveal, setReveal] = useState(false);
  const [comparing, setComparing] = useState(false);
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);

  useEffect(() => subscribe(session, setModel, onError), [session, onError]);

  // While capturing, keep the newest step in view so each action shows up as you do it.
  const live = model?.live ?? false;
  const stepCount = model?.steps.length ?? 0;
  useEffect(() => {
    if (!live || stepCount < 2) return;
    document.getElementById(`step-col-${stepCount - 1}`)?.scrollIntoView({ behavior: 'smooth', inline: 'end', block: 'nearest' });
    document.querySelector('.strip-card:last-child')?.scrollIntoView({ behavior: 'smooth', inline: 'end', block: 'nearest' });
  }, [live, stepCount]);

  const selectStep = (step: number) => {
    setSelectedStep(step);
    document.getElementById(`step-col-${step}`)?.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
  };
  const set = <K extends keyof Filters>(key: K, value: Filters[K]) => setFilters((f) => ({ ...f, [key]: value }));

  return (
    <>
      <div className="toolbar">
        {model ? <StatusPills model={model} /> : null}
        <input placeholder="search names, values, URLs" value={filters.search} onChange={(e) => set('search', e.target.value)} />
        <label>
          <input type="checkbox" checked={filters.changedOnly} onChange={(e) => set('changedOnly', e.target.checked)} /> changed only
        </label>
        <label>
          <input type="checkbox" checked={filters.hideTrackers} onChange={(e) => set('hideTrackers', e.target.checked)} /> hide trackers
        </label>
        <label title="Show password fields in request bodies">
          <input type="checkbox" checked={reveal} onChange={(e) => setReveal(e.target.checked)} /> reveal passwords
        </label>
        <button onClick={() => setComparing(true)}>compare</button>
        <a className="button" href={api.exportUrl(session)} download title="session.json timeline + screenshots + large bodies, as a zip">
          download export
        </a>
      </div>
      {model ? (
        <>
          <StepStrip session={session} steps={model.steps} selected={selectedStep} onSelect={selectStep} />
          <div className="body">
            <Matrix model={model} filters={filters} selectedStep={selectedStep} onSelect={setSelection} />
            {selection ? <Drawer session={session} model={model} selection={selection} reveal={reveal} onSelect={setSelection} onClose={() => setSelection(null)} /> : null}
            {comparing ? <CompareView current={session} sessions={sessions} onClose={() => setComparing(false)} /> : null}
          </div>
        </>
      ) : (
        <p className="muted pad">Loading session…</p>
      )}
    </>
  );
}

export default function App() {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [session, setSession] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    api.sessions().then(
      (list) => {
        setSessions(list);
        setSession((current) => current || (list.find((s) => s.live) ?? list[0])?.id || '');
      },
      (e: Error) => setError(e.message),
    );
  }, []);

  return (
    <div className="app">
      <header>
        <h1>
          <img src={icon} alt="" className="logo" />
          SessionLens
        </h1>
        <select value={session} onChange={(e) => setSession(e.target.value)}>
          {sessions.map((s) => (
            <option key={s.id} value={s.id}>
              {s.id}
              {s.live ? ' (live)' : ''}
            </option>
          ))}
        </select>
      </header>
      {error ? <div className="error banner">{error}</div> : null}
      {session ? (
        <SessionView key={session} session={session} sessions={sessions} onError={setError} />
      ) : !error ? (
        <p className="muted pad">No sessions yet. Run: python -m sessionlens start</p>
      ) : null}
    </div>
  );
}
