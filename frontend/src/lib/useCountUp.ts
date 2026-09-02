import { useEffect, useRef, useState } from "react";

const DURATION_MS = 600;

function prefersReducedMotion(): boolean {
  return window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
}

/**
 * Animates a number from 0 to `value` once on mount/value-change, per
 * latest.md section 26 ("animated count-up once on load, do not continuously
 * animate"). Under prefers-reduced-motion (section 55) the final value is
 * derived directly at render time instead — nothing to animate towards, so
 * no state/effect is involved for that path.
 */
export function useCountUp(value: number | null): number | null {
  const [animated, setAnimated] = useState(value ?? 0);
  const previous = useRef(value ?? 0);
  const reducedMotion = prefersReducedMotion();

  useEffect(() => {
    if (value === null || reducedMotion) return;

    const from = previous.current;
    const target = value;
    const start = performance.now();
    let frame: number;

    function tick(now: number) {
      const progress = Math.min(1, (now - start) / DURATION_MS);
      setAnimated(Math.round(from + (target - from) * progress));
      if (progress < 1) frame = requestAnimationFrame(tick);
      else previous.current = target;
    }

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [value, reducedMotion]);

  if (value === null) return null;
  if (reducedMotion) return value;
  return animated;
}
