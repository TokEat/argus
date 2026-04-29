import { useRef, useEffect, type RefObject } from 'react';
import gsap from 'gsap';

/**
 * 入场动画：目标元素从下方淡入，支持 stagger
 */
export function useStaggerIn<T extends HTMLElement = HTMLDivElement>(
  selector: string,
  deps: unknown[] = [],
): RefObject<T | null> {
  const ref = useRef<T | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const els = ref.current.querySelectorAll(selector);
    if (els.length === 0) return;

    const ctx = gsap.context(() => {
      gsap.from(els, {
        y: 24,
        opacity: 0,
        duration: 0.45,
        stagger: 0.06,
        ease: 'power2.out',
        clearProps: 'transform,opacity',
      });
    }, ref);

    return () => ctx.revert();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return ref;
}

/**
 * 数字滚动（CountUp）— 将元素的文本从 0 滚动到目标值
 */
export function useCountUp<T extends HTMLElement = HTMLDivElement>(
  value: number,
  selector: string,
): RefObject<T | null> {
  const ref = useRef<T | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const el = ref.current.querySelector(selector);
    if (!el) return;

    const obj = { val: 0 };
    const tween = gsap.to(obj, {
      val: value,
      duration: 1,
      ease: 'power2.out',
      onUpdate: () => {
        el.textContent = String(Math.round(obj.val));
      },
    });

    return () => { tween.kill(); };
  }, [value, selector]);

  return ref;
}

/**
 * 单个元素入场动画
 */
export function useFadeIn<T extends HTMLElement = HTMLDivElement>(
  deps: unknown[] = [],
): RefObject<T | null> {
  const ref = useRef<T | null>(null);

  useEffect(() => {
    if (!ref.current) return;

    const ctx = gsap.context(() => {
      gsap.from(ref.current, {
        opacity: 0,
        y: 16,
        duration: 0.4,
        ease: 'power2.out',
        clearProps: 'transform,opacity',
      });
    }, ref);

    return () => ctx.revert();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return ref;
}
