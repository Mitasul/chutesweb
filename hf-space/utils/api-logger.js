/**
 * HF-space logger stub: 禁用文件日志与控制台日志。
 * 仅保持 axios 拦截器结构以避免依赖错误。
 */
function createAxiosLogger(axiosInstance) {
  // request pass-through
  axiosInstance.interceptors.request.use(
    (config) => config,
    (error) => Promise.reject(error)
  );
  // response pass-through
  axiosInstance.interceptors.response.use(
    (response) => response,
    (error) => Promise.reject(error)
  );
}

function logApiRequest() { /* noop */ }
function readApiLogs() { return []; }

module.exports = { createAxiosLogger, logApiRequest, readApiLogs };
