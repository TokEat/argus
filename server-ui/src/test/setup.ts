import '@testing-library/jest-dom/vitest';
import { vi } from 'vitest';

const storage = new Map<string, string>();

const localStorageMock = {
    getItem: vi.fn((key: string) => storage.get(key) ?? null),
    setItem: vi.fn((key: string, value: string) => {
        storage.set(key, value);
    }),
    removeItem: vi.fn((key: string) => {
        storage.delete(key);
    }),
    clear: vi.fn(() => {
        storage.clear();
    }),
};

Object.defineProperty(window, 'localStorage', {
    value: localStorageMock,
    writable: true,
});

Object.defineProperty(globalThis, 'localStorage', {
    value: localStorageMock,
    writable: true,
});

Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockImplementation((query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
    })),
});

Object.defineProperty(globalThis, 'matchMedia', {
    writable: true,
    value: window.matchMedia,
});

const getComputedStyle = window.getComputedStyle.bind(window);
Object.defineProperty(window, 'getComputedStyle', {
    value: (element: Element) => getComputedStyle(element),
});

// react-resizable 使用节点引用测量 DOM；测试环境中的 AntD 布局不会自动赋予该引用。
vi.mock('react-resizable', () => ({
    Resizable: ({ children }: { children: React.ReactNode }) => children,
}));

class ResizeObserverMock {
    observe = vi.fn();
    unobserve = vi.fn();
    disconnect = vi.fn();
}
Object.defineProperty(globalThis, 'ResizeObserver', { value: ResizeObserverMock, writable: true });
