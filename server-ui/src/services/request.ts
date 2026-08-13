import axios from 'axios';
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';

const request: AxiosInstance = axios.create({
    baseURL: '/api/v1',
    timeout: 30000,
    headers: { 'Content-Type': 'application/json' },
});

request.interceptors.request.use((config) => {
    const token = localStorage.getItem('token');
    (config as AxiosRequestConfig & { __authTokenSnapshot?: string }).__authTokenSnapshot = token || '';
    if (token) config.headers.Authorization = `Bearer ${token}`;
    return config;
}, (error) => Promise.reject(error));

request.interceptors.response.use((response: AxiosResponse) => response.data, (error) => {
    if (error.response?.status === 401) {
        const currentToken = localStorage.getItem('token') || '';
        const snapshotToken = ((error.config as AxiosRequestConfig & { __authTokenSnapshot?: string })?.__authTokenSnapshot || '') as string;
        const isStale401 = snapshotToken !== '' && currentToken !== '' && snapshotToken !== currentToken;
        if (!isStale401 && !window.location.pathname.includes('/login')) {
            localStorage.removeItem('token');
            window.location.href = '/login';
        }
    }
    const data = error.response?.data;
    const message = typeof data === 'string' ? data.trim() : data?.error || data?.message || error.message;
    return Promise.reject(message);
});

export default request;
