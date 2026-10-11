import { api } from '../api';
import type { Step } from '../types';
import { relTime } from '../util';

interface Props {
  session: string;
  steps: Step[];
  selected: number | null;
  onSelect: (step: number) => void;
}

const ICON: Record<Step['kind'], string> = { start: '🚀', action: '👆', nav: '🧭', spa: '↪️' };

export function StepStrip({ session, steps, selected, onSelect }: Props) {
  const t0 = steps[0]?.t ?? 0;
  return (
    <div className="strip">
      {steps.map((step) => (
        <button key={step.id} className={`strip-card ${selected === step.id ? 'selected' : ''}`} onClick={() => onSelect(step.id)} title={step.url ?? step.label}>
          {step.screenshot !== null ? <img src={api.screenshotUrl(session, step.screenshot)} alt="" loading="lazy" /> : <div className="no-shot">{ICON[step.kind]}</div>}
          <div className="strip-label">
            <b>#{step.id}</b> {step.label}
          </div>
          <div className="strip-time">{relTime(step.t, t0)}</div>
        </button>
      ))}
    </div>
  );
}
