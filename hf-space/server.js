/**
 * Chutes Image App - Express Server
 * Features:
 * - Static hosting
 * - /api/models: fetch remote models (if MODELS_URL) or fallback to local data/models.json
 * - /api/generate: proxy to chutes generate API with robust payload strategy and error handling
 * - Security (helmet), CORS, compression, logging, timeouts
 */

require('dotenv').config();

const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const { createAxiosLogger } = require('./utils/api-logger');

const app = express();

// Env
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const STATIC_DIR = process.env.STATIC_DIR || 'public';
const GENERATE_API_URL = process.env.GENERATE_API_URL || 'https://image.chutes.ai/generate';
const MODELS_URL = process.env.MODELS_URL || '';
const CHUTES_API_TOKEN = process.env.CHUTES_API_TOKEN || '';
const MOCK_MODE = /^true$/i.test(process.env.MOCK_MODE || 'false');
const TIMEOUT_MS = parseInt(process.env.TIMEOUT_MS || '120000', 10);
const LOG_LEVEL = process.env.LOG_LEVEL || 'dev';
// Allow end-user to optionally provide API key from frontend (header x-api-key)
const ALLOW_CLIENT_API_KEY = /^true$/i.test(process.env.ALLOW_CLIENT_API_KEY || 'true');
// Strict switches to close any possibility of routing/fallback
// - STRICT_NO_ROUTING=true 不做本地映射，除非前端或调用方显式传 upstream_id
// - STRICT_NO_FALLBACK=true 强制禁用回落（即使前端未设置 no_fallback）
const STRICT_NO_ROUTING = /^true$/i.test(process.env.STRICT_NO_ROUTING || 'false');
const STRICT_NO_FALLBACK = /^true$/i.test(process.env.STRICT_NO_FALLBACK || 'true');
// Auto fallback to another model when upstream capacity/infrastructure errors
const AUTO_FALLBACK = /^true$/i.test(process.env.AUTO_FALLBACK || 'true');
// Retry strategy for transient upstream errors
const RETRIES = parseInt(process.env.RETRIES || '2', 10);
const RETRY_BASE_MS = parseInt(process.env.RETRY_BASE_MS || '800', 10);
// Upstream auth mode: '' or 'x-api-key' (default: Authorization Bearer)
const UPSTREAM_AUTH_MODE = process.env.UPSTREAM_AUTH_MODE || '';
// Force sending minimal payload (only prompt) to upstream (default false)
const FORCE_MINIMAL = /^true$/i.test(process.env.FORCE_MINIMAL || 'false');

// Middlewares
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  // Allow embedding on Hugging Face Spaces (disable X-Frame-Options)
  frameguard: false,
  // Avoid COOP/COEP blocking when embedded in an iframe
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
  crossOriginEmbedderPolicy: false,
  originAgentCluster: false
}));

// Enable CSP and allow inline script/style for this SPA.
// Also allow connections to the upstream image API.
// Allow embedding inside Hugging Face Spaces iframe via frame-ancestors/frame-src
app.use(helmet.contentSecurityPolicy({
  useDefaults: true,
  directives: {
    "default-src": ["'self'"],
    "script-src": ["'self'", "'unsafe-inline'"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:", "blob:"],
    "font-src": ["'self'", "data:"],
    "connect-src": ["'self'", "https://image.chutes.ai"],
    "media-src": ["'self'", "data:", "blob:"],
    "frame-src": ["'self'", "https://huggingface.co", "https://*.huggingface.co", "https://*.hf.space"],
    "frame-ancestors": ["'self'", "https://huggingface.co", "https://*.huggingface.co", "https://*.hf.space"]
  }
}));

// Ensure no legacy X-Frame-Options header blocks embedding
app.use((req, res, next) => {
  res.removeHeader('X-Frame-Options');
  next();
});

app.use(cors());
app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(morgan(LOG_LEVEL));

// Static files
const staticPath = path.resolve(__dirname, STATIC_DIR);
app.use(express.static(staticPath, {
  etag: true,
  lastModified: true,
  maxAge: '1h',
  setHeaders: (res, filePath) => {
    if (/\.(html)$/.test(filePath)) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

// Expose studio assets (notification sound)
const studioPath = path.resolve(__dirname, 'studio');
app.use('/studio', express.static(studioPath, {
  etag: true,
  lastModified: true,
  maxAge: '1h'
}));

// Utilities
const localModelsPath = path.resolve(__dirname, 'data', 'models.json');

/**
 * Read local models fallback file.
 * @returns {Promise<Array>}
 */
async function readLocalModels() {
  try {
    const raw = await fs.promises.readFile(localModelsPath, 'utf-8');
    const data = JSON.parse(raw);
    if (Array.isArray(data)) return data;
    if (Array.isArray(data.models)) return data.models;
    return [];
  } catch (err) {
    console.error('Failed to read local models:', err.message);
    return [];
  }
}

/**
 * Fetch remote models from MODELS_URL if provided.
 * Expected to return either Array or { models: [] }
 * @param {string} tokenOverride optional API token per-request
 * @returns {Promise<Array|null>}
 */
// 创建用于获取模型列表的axios实例并启用日志记录
const axiosModels = axios.create({
  timeout: Math.min(TIMEOUT_MS, 30000),
  validateStatus: () => true
});
createAxiosLogger(axiosModels);

async function fetchRemoteModels(tokenOverride = '') {
  if (!MODELS_URL) return null;
  try {
    const resp = await axiosModels.get(MODELS_URL, {
      headers: {
        'Content-Type': 'application/json',
        ...(tokenOverride ? { 'Authorization': `Bearer ${tokenOverride}` } : (CHUTES_API_TOKEN ? { 'Authorization': `Bearer ${CHUTES_API_TOKEN}` } : {}))
      }
    });
    const payload = resp.data;
    if (Array.isArray(payload)) return payload;
    if (payload && Array.isArray(payload.models)) return payload.models;
    return null;
  } catch (err) {
    console.error('Failed to fetch remote models:', err.message);
    return null;
  }
}

/**
 * Merge "free" flags from local list into remote list by model id or name
 */
function mergeFreeFlags(remoteList, localList) {
  const freeMap = new Map();
  for (const m of localList) {
    const key = (m.id || m.name || '').toLowerCase();
    if (key) freeMap.set(key, !!m.free);
  }
  return remoteList.map(m => {
    const key = (m.id || m.name || '').toLowerCase();
    const free = freeMap.has(key) ? freeMap.get(key) : (typeof m.free === 'boolean' ? m.free : false);
    return { ...m, free };
  });
}

/**
 * Clamp helper
 */
function clamp(n, min, max) {
  if (typeof n !== 'number' || Number.isNaN(n)) return min;
  return Math.max(min, Math.min(max, n));
}

/**
 * Axios instance for generate
 */
const axiosGen = axios.create({
  timeout: TIMEOUT_MS,
  responseType: 'arraybuffer', // for image/jpeg
  validateStatus: () => true
});

// 启用API日志记录
createAxiosLogger(axiosGen);

function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

// Routes
app.get('/api/health', (req, res) => {
  res.json({ ok: true, mock: MOCK_MODE, version: '1.0.0', allowClientKey: ALLOW_CLIENT_API_KEY });
});

/**
 * GET /api/models
 * 1) Try remote MODELS_URL
 * 2) Fallback local data/models.json
 * 3) Ensure each model has: { id, name, free }
 */
app.get('/api/models', async (req, res) => {
  try {
    const localList = await readLocalModels();
    const apiToken = req.headers['x-api-key'] || CHUTES_API_TOKEN;
    let models = await fetchRemoteModels(apiToken);
    if (models && models.length) {
      // Normalize remote items
      models = models.map((m, idx) => {
        const id = (m.id || m.slug || m.model || m.name || `model-${idx}`).toString();
        const name = (m.name || id).toString();
        const free = typeof m.free === 'boolean' ? m.free : false;
        return { id, name, free };
      });
      // Merge free flags from local mapping
      if (localList.length) {
        // Merge free flags for models that exist remotely
        models = mergeFreeFlags(models, localList);
        // Also append local-only models (union), so new models in local config are visible in frontend
        const remoteKeys = new Set(models.map(m => ((m.id || m.name || '') + '').toLowerCase()));
        for (const lm of localList) {
          const key = ((lm.id || lm.name || '') + '').toLowerCase();
          if (key && !remoteKeys.has(key)) {
            const id = (lm.id || lm.name || '').toString();
            const name = (lm.name || id).toString();
            const free = !!lm.free;
            models.push({ id, name, free });
            remoteKeys.add(key);
          }
        }
      }
      return res.json({ source: 'remote', models });
    }

    // Fallback to local
    const normalized = localList.map((m, idx) => {
      const id = (m.id || m.slug || m.model || m.name || `model-${idx}`).toString();
      const name = (m.name || id).toString();
      const free = !!m.free;
      return { id, name, free };
    });
    return res.json({ source: 'local', models: normalized });
  } catch (err) {
    console.error('GET /api/models failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to load models' });
  }
});

/**
 * POST /api/generate
 * Body supports two shapes:
 * A) { model, input_args: { prompt, negative_prompt, width, height, guidance_scale, num_inference_steps, seed } }
 * B) { model, prompt, negative_prompt, width, height, guidance_scale, num_inference_steps, seed }
 *
 * Server will attempt upstream with A first, then fallback to B if A fails.
 * Returns JSON: { ok, image (base64 data URL), contentType, meta, tried }
 */
app.post('/api/generate', async (req, res) => {
  try {
    if (MOCK_MODE) {
      // Return a tiny transparent PNG as mock
      const pngBase64 =
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGMAAQAABQABDQottQAAAABJRU5ErkJggg==';
      return res.json({
        ok: true,
        image: `data:image/png;base64,${pngBase64}`,
        contentType: 'image/png',
        meta: { mock: true }
      });
    }

    const body = req.body || {};
    const flat = {
      model: (body.model || (body.input_args && body.input_args.model) || '').toString(),
      prompt: (body.prompt ?? (body.input_args ? body.input_args.prompt : undefined) ?? '').toString(),
      negative_prompt: (body.negative_prompt ?? (body.input_args ? body.input_args.negative_prompt : undefined) ?? '').toString(),
      width: clamp(parseInt(body.width ?? (body.input_args ? body.input_args.width : 1024), 10) || 1024, 128, 2048),
      height: clamp(parseInt(body.height ?? (body.input_args ? body.input_args.height : 1024), 10) || 1024, 128, 2048),
      guidance_scale: clamp(parseFloat(body.guidance_scale ?? (body.input_args ? body.input_args.guidance_scale : 7.5)) || 7.5, 0, 20),
      num_inference_steps: clamp(parseInt(body.num_inference_steps ?? (body.input_args ? body.input_args.num_inference_steps : 25), 10) || 25, 1, 100),
      // Z-Image-Turbo 专属字段（可选）
      shift: clamp(parseFloat(body.shift ?? (body.input_args ? body.input_args.shift : 3)) || 3, 1, 10),
      max_sequence_length: clamp(parseInt(body.max_sequence_length ?? (body.input_args ? body.input_args.max_sequence_length : 512), 10) || 512, 256, 2048),
      // Seed: support top-level or input_args.seed; if missing/null -> null (omit from payload)
      seed: (() => {
        const raw = (body.seed ?? (body.input_args ? body.input_args.seed : undefined));
        if (raw === null || raw === undefined || raw === '') return null;
        const n = Number(raw);
        if (!Number.isFinite(n)) return null;
        const clamped = Math.max(0, Math.min(4294967295, Math.trunc(n)));
        return clamped;
      })()
    };

    if (!flat.prompt || !flat.model) {
      return res.status(400).json({ ok: false, error: 'model and prompt are required' });
    }

    // Resolve an upstream model id via local mapping, with optional client override.
    const localList = await readLocalModels();
    function resolveUpstream(id) {
      const key = (id || '').toLowerCase();
      for (const m of localList) {
        const mid = (m.id || '').toLowerCase();
        const name = (m.name || '').toLowerCase();
        if (mid === key || name === key) {
          if (m.upstream_id) return m.upstream_id;
        }
      }
      return id;
    }
    const overrideUpstream = (body.upstream_id ?? (body.input_args ? body.input_args.upstream_id : undefined));
    let targetModel = (overrideUpstream && String(overrideUpstream).trim())
      ? String(overrideUpstream).trim()
      : (STRICT_NO_ROUTING ? flat.model : resolveUpstream(flat.model));
    // honor global strict no-fallback if enabled
    const NO_FALLBACK = STRICT_NO_FALLBACK || Boolean(body.no_fallback ?? (body.input_args ? body.input_args.no_fallback : false));

    // Resolve additional upstream configuration from local model config
    function getModelConfig(list, idOrName) {
      const key = (idOrName || '').toLowerCase();
      for (const m of list) {
        const mid = (m.id || '').toLowerCase();
        const name = (m.name || '').toLowerCase();
        if (mid === key || name === key) return m;
      }
      return null;
    }
    const cfg = getModelConfig(localList, flat.model);
    let generateUrl = (cfg && cfg.upstream_url) ? cfg.upstream_url : GENERATE_API_URL;
    let preferMinimal = FORCE_MINIMAL || !!(cfg && cfg.minimal === true);
    const isHidream = (
      typeof flat.model === 'string' && flat.model.toLowerCase() === 'hidream'
    ) || /hidream/i.test(generateUrl) || /hidream/i.test(String(targetModel || ''));
    const isQwenEdit = (
      typeof flat.model === 'string' && flat.model.toLowerCase() === 'qwen-image-edit'
    ) || /qwen-image-edit/i.test(generateUrl) || /qwen-image-edit/i.test(String(targetModel || ''));
    const isZImageTurbo = (
      typeof flat.model === 'string' && flat.model.toLowerCase() === 'z-image-turbo'
    ) || /z-image-turbo/i.test(generateUrl) || /z-image-turbo/i.test(String(targetModel || ''));


    const apiToken = req.headers['x-api-key'] || CHUTES_API_TOKEN;
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'image/png,image/jpeg,application/octet-stream,application/json',
      ...(apiToken ? { 'Authorization': `Bearer ${apiToken}` } : {})
    };

    // hidream: 优先使用 models.json 的 upstream_url；否则使用 HIDREAM_UPSTREAM_URL；否则保持默认 GENERATE_API_URL
    if (isHidream) {
      const envUrl = process.env.HIDREAM_UPSTREAM_URL || '';
      function isValidUrl(u) {
        try { new URL(u); return true; } catch { return false; }
      }
      if (cfg && cfg.upstream_url && isValidUrl(cfg.upstream_url)) {
        generateUrl = cfg.upstream_url;
      } else if (envUrl && isValidUrl(envUrl)) {
        generateUrl = envUrl;
      }
    }

    // Normalize special-case upstream ids that differ from local display ids
    // qwen-image-edit 在上游共用 qwen-image 的路由/标识
    if (isQwenEdit && String(targetModel || '').toLowerCase() === 'qwen-image-edit') {
      targetModel = 'qwen-image';
    }

    // Pass-through extras (e.g., image_b64s, true_cfg_scale, resolution, etc.)
    const inputExtras = (body && typeof body.input_args === 'object') ? { ...body.input_args } : {};
    if (isHidream) {
      // hidream 仅接受 resolution；确保存在并移除 width/height 噪声
      if (!inputExtras.resolution) {
        inputExtras.resolution = `${flat.width}x${flat.height}`;
      }
      delete inputExtras.width;
      delete inputExtras.height;
    }
    if (!isQwenEdit) {
      // 非 qwen-image-edit 时不传参考图与 true_cfg_scale
      delete inputExtras.image_b64s;
      delete inputExtras.true_cfg_scale;
    }

    // Build top-level extras for flat payloads (some upstreams expect image_b64s/true_cfg_scale at top-level)
    const topLevelExtras = {};
    const maybeImageB64s = (body && (body.image_b64s ?? (body.input_args && body.input_args.image_b64s)));
    const maybeTrueCfg = (body && (body.true_cfg_scale ?? (body.input_args && body.input_args.true_cfg_scale)));
    if (isQwenEdit) {
      if (maybeImageB64s) topLevelExtras.image_b64s = maybeImageB64s;
      if (maybeTrueCfg !== undefined && maybeTrueCfg !== null) topLevelExtras.true_cfg_scale = maybeTrueCfg;
    }

    // qwen-image-edit: 校验参考图数量（1-3）
    if (isQwenEdit) {
      const imgs = inputExtras.image_b64s || topLevelExtras.image_b64s;
      const validCount = Array.isArray(imgs) ? imgs.length : 0;
      if (validCount < 1 || validCount > 3) {
        return res.status(400).json({ ok: false, error: 'qwen-image-edit 需要 1-3 张参考图 (image_b64s)' });
      }
    }

    const commonArgs = {
      prompt: flat.prompt,
      negative_prompt: flat.negative_prompt || '',
      guidance_scale: flat.guidance_scale,
      num_inference_steps: flat.num_inference_steps,
      ...(flat.seed !== null ? { seed: flat.seed } : {})
    };
    const variantA = {
      model: targetModel,
      input_args: isHidream
        ? { ...inputExtras, ...commonArgs }
        : { ...inputExtras, ...commonArgs, width: flat.width, height: flat.height }
    };

    const variantB = isHidream
      ? {
          model: targetModel,
          input_args: { ...inputExtras, ...commonArgs }
        }
      : {
          model: targetModel,
          ...topLevelExtras,
          ...commonArgs,
          width: flat.width,
          height: flat.height
        };

    // Hidream-specific flat payload expected by chutes-hidream endpoint (no input_args)
    const variantHidreamFlat = isHidream ? {
      prompt: flat.prompt,
      resolution: (inputExtras && inputExtras.resolution) ? String(inputExtras.resolution) : `${flat.width}x${flat.height}`,
      guidance_scale: flat.guidance_scale,
      num_inference_steps: flat.num_inference_steps,
      ...(flat.seed !== null ? { seed: flat.seed } : {})
    } : null;

    // Minimal payload (some models reject extended fields). Include size/steps/seed for hunyuan-image-3 compatibility
    const variantCMinimal = {
      model: targetModel,
      input_args: {
        prompt: flat.prompt,
        size: `${flat.width}x${flat.height}`,
        steps: flat.num_inference_steps,
        ...(flat.seed !== null ? { seed: flat.seed } : {})
      }
    };

    // Flat minimal payload for model-specific upstreams that expect top-level { prompt }
    const variantFlatMinimal = {
      prompt: flat.prompt,
      size: `${flat.width}x${flat.height}`,
      steps: flat.num_inference_steps,
      ...(flat.seed !== null ? { seed: flat.seed } : {})
    };

    // Qwen-image-edit: official top-level flat payload (no model, includes refs)
    const variantQwenFlat = isQwenEdit ? {
      prompt: flat.prompt,
      negative_prompt: flat.negative_prompt || '',
      width: flat.width,
      height: flat.height,
      guidance_scale: flat.guidance_scale,
      num_inference_steps: flat.num_inference_steps,
      ...(flat.seed !== null ? { seed: flat.seed } : {}),
      ...(inputExtras && inputExtras.image_b64s ? { image_b64s: inputExtras.image_b64s } : (topLevelExtras.image_b64s ? { image_b64s: topLevelExtras.image_b64s } : {})),
      ...(inputExtras && (inputExtras.true_cfg_scale !== undefined && inputExtras.true_cfg_scale !== null) ? { true_cfg_scale: inputExtras.true_cfg_scale } : (topLevelExtras.true_cfg_scale !== undefined ? { true_cfg_scale: topLevelExtras.true_cfg_scale } : {}))
    } : null;

    // duplicate removed

    async function tryCall(payload, label, url) {
      const resp = await axiosGen.post(url, payload, { headers });
      const ctype = (resp.headers && (resp.headers['content-type'] || resp.headers['Content-Type'])) || '';
      const status = resp.status;

      // Success: image buffer
      if (status >= 200 && status < 300 && /image\//i.test(ctype)) {
        const base64 = Buffer.from(resp.data).toString('base64');
        return { ok: true, imageBase64: base64, contentType: ctype, tried: label };
      }

      // Success: JSON response that may contain base64 or data URL
      if (status >= 200 && status < 300 && /application\/json/i.test(ctype)) {
        let raw = '';
        try { raw = Buffer.from(resp.data).toString(); } catch (e) {}
        try {
          const j = JSON.parse(raw || '{}');
          // Common patterns: { image: "data:..."} or { image: "<base64>", contentType: "image/jpeg" } or { data: "<base64>" }
          if (j && j.image) {
            if (typeof j.image === 'string' && j.image.startsWith('data:')) {
              // Already data URL; extract base64 and contentType
              const match = /^data:([^;]+);base64,(.*)$/i.exec(j.image);
              if (match) {
                return { ok: true, imageBase64: match[2], contentType: match[1], tried: label };
              }
            } else if (typeof j.image === 'string') {
              const ct = (j.contentType || 'image/jpeg');
              return { ok: true, imageBase64: j.image, contentType: ct, tried: label };
            }
          }
          if (j && j.data && typeof j.data === 'string') {
            const ct = (j.contentType || 'image/jpeg');
            return { ok: true, imageBase64: j.data, contentType: ct, tried: label };
          }
        } catch (e) {
          // fallthrough to error mapping below
        }
      }

      // Error handling branch (non-2xx or unrecognized payload)
      let raw = '';
      try {
        raw = Buffer.from(resp.data).toString();
      } catch (e) {}

      // Friendly diagnostics mapping
      let code = 'UPSTREAM_ERROR';
      let hint = '';
      let mappedStatus = status;
      let detailText = '';
      try {
        const j = JSON.parse(raw);
        detailText = j && (j.detail || j.message || j.error || '');
      } catch (e) {
        detailText = raw;
      }

      const lower = (detailText || '').toLowerCase();
      if (lower.includes('exhausted all available targets')) {
        code = 'UPSTREAM_CAPACITY_EXHAUSTED';
        hint = '上游容量不足（GPU/目标不可用或排队中），请稍后重试、换模型，或降低分辨率/步数。';
        mappedStatus = 503; // service unavailable
      } else if (status === 404 && lower.includes('model not found')) {
        code = 'UPSTREAM_MODEL_NOT_FOUND';
        hint = '上游模型不存在或标识不匹配。请更换模型，或在 data/models.json 为该模型添加正确的 \"upstream_id\" 映射后重试。';
      } else if (status === 400 && (lower.includes('invalid request') || lower.includes('invalid input'))) {
        code = 'UPSTREAM_INVALID_PARAMS';
        hint = '上游参数不接受：尝试使用最小输入（仅 prompt）重试。';
      }

      const err = new Error(hint || `Upstream ${label} failed: ${status} ${ctype} ${raw || ''}`);
      err.status = mappedStatus;
      err.code = code;
      err.hint = hint;
      throw err;
    }

    let result;

    // z-image-turbo: send upstream payload with only supported fields
    if (isZImageTurbo) {
      const variantZFlat = {
        prompt: flat.prompt,
        height: flat.height,
        width: flat.width,
        num_inference_steps: flat.num_inference_steps,
        guidance_scale: flat.guidance_scale,
        shift: flat.shift,
        max_sequence_length: flat.max_sequence_length,
        ...(flat.seed !== null ? { seed: flat.seed } : {})
      };
      try {
        result = await tryCall(variantZFlat, 'z-flat', generateUrl);
      } catch (eZ) {
        const status = eZ.status || 502;
        return res.status(status).json({
          ok: false,
          error: eZ.hint || eZ.message || 'Upstream error',
          code: eZ.code || 'UPSTREAM_ERROR',
          upstream_model: targetModel
        });
      }
    }
    
    // If the model prefers minimal payload, choose ordering per model.
    // For hunyuan-image-3: nested-minimal (input_args with size) FIRST to ensure size is honored.
    if (preferMinimal) {
      const isHunyuan =
        (typeof flat.model === 'string' && flat.model.toLowerCase() === 'hunyuan-image-3') ||
        /hunyuan-image-3/i.test(generateUrl) ||
        /hunyuan-image-3/i.test(String(targetModel || ''));
      if (isHunyuan) {
        try {
          result = await tryCall(variantCMinimal, 'nested-minimal', generateUrl);
        } catch (e0) {}
        if (!result) {
          try {
            result = await tryCall(variantFlatMinimal, 'flat-minimal', generateUrl);
          } catch (e1) {}
        }
      } else {
        try {
          result = await tryCall(variantFlatMinimal, 'flat-minimal', generateUrl);
        } catch (e0) {}
        if (!result) {
          try {
            result = await tryCall(variantCMinimal, 'nested-minimal', generateUrl);
          } catch (e1) {}
        }
      }
    }

    // Only try full payload if minimal didn't succeed
    if (!result) {
      let lastError = null;

      if (!result) {
        try { result = await tryCall(variantA, 'nested', generateUrl); }
        catch (e1) { lastError = e1; }
      }

      if (!result) {
        try { result = await tryCall(variantB, 'flat', generateUrl); }
        catch (e2) { lastError = e2; }
      }

      // qwen-image-edit official flat payload (no model)
      if (!result && isQwenEdit && variantQwenFlat) {
        try { result = await tryCall(variantQwenFlat, 'qwen-flat', generateUrl); }
        catch (eQ) { lastError = eQ; }
      }

      // hidream official flat payload (no model)
      if (!result && isHidream && variantHidreamFlat) {
        try { result = await tryCall(variantHidreamFlat, 'hidream-flat', generateUrl); }
        catch (eH) { lastError = eH; }
      }

      if (!result) {
        const capacityCodes = ['UPSTREAM_CAPACITY_EXHAUSTED','UPSTREAM_NO_INSTANCES','UPSTREAM_INFRASTRUCTURE','UPSTREAM_BAD_GATEWAY'];
        if (AUTO_FALLBACK && !NO_FALLBACK && lastError && capacityCodes.includes(lastError.code || '')) {
          function chooseFallback(currentId, list) {
            const key = (currentId || '').toLowerCase();
            const free = list.filter(m => m.free && (m.id || m.name || '').toLowerCase() !== key);
            if (free.length) return (free[0].upstream_id || free[0].id || free[0].name);
            const any = list.find(m => (m.id || m.name || '').toLowerCase() !== key);
            if (any) return (any.upstream_id || any.id || any.name);
            return null;
          }
          const fallbackModel = chooseFallback(targetModel, localList);
          if (fallbackModel && fallbackModel !== targetModel) {
            const fbA = { ...variantA, model: fallbackModel };
            const fbB = { ...variantB, model: fallbackModel };
            const fbCfg = getModelConfig(localList, fallbackModel);
            const fbUrl = (fbCfg && fbCfg.upstream_url) ? fbCfg.upstream_url : GENERATE_API_URL;

            try { result = await tryCall(fbA, 'nested-fallback', fbUrl); }
            catch (e3) {
              try { result = await tryCall(fbB, 'flat-fallback', fbUrl); }
              catch (e4) {
                const status = e4.status || 502;
                return res.status(status).json({
                  ok: false,
                  error: e4.hint || e4.message || 'Upstream error',
                  code: e4.code || 'UPSTREAM_ERROR',
                  upstream_model: targetModel,
                  fallback_model: fallbackModel
                });
              }
            }

            return res.json({
              ok: true,
              image: `data:${result.contentType};base64,${result.imageBase64}`,
              contentType: result.contentType,
              meta: {
                model: flat.model,
                upstream_model: targetModel,
                fallback_used: true,
                fallback_model: fallbackModel,
                width: flat.width,
                height: flat.height,
                guidance_scale: flat.guidance_scale,
                num_inference_steps: flat.num_inference_steps,
                seed: flat.seed
              },
              tried: result.tried
            });
          }
        }

        const status = (lastError && lastError.status) || 502;
        return res.status(status).json({
          ok: false,
          error: (lastError && (lastError.hint || lastError.message)) || 'Upstream error',
          code: (lastError && lastError.code) || 'UPSTREAM_ERROR',
          upstream_model: targetModel
        });
      }
    }

    return res.json({
      ok: true,
      image: `data:${result.contentType};base64,${result.imageBase64}`,
      contentType: result.contentType,
      meta: {
        model: flat.model,
        upstream_model: targetModel,
        width: flat.width,
        height: flat.height,
        guidance_scale: flat.guidance_scale,
        num_inference_steps: flat.num_inference_steps,
        seed: flat.seed
      },
      tried: result.tried
    });
  } catch (err) {
    console.error('POST /api/generate failed:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Favicon placeholder to avoid noisy 404 in dev
app.get('/favicon.ico', (req, res) => {
 res.status(204).end();
});

// Fallback to index.html for direct root access
app.get('/', (req, res) => {
 res.sendFile(path.join(staticPath, 'index.html'));
});

// Start server
app.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
});