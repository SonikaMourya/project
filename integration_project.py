// src/config/index.js
/**
 * Application configuration
 */
module.exports = {
  shopify: {
    clientId: process.env.SHOPIFY_CLIENT_ID,
    clientSecret: process.env.SHOPIFY_CLIENT_SECRET,
    redirectUri: process.env.SHOPIFY_REDIRECT_URI,
    scopes: 'read_products,write_products,read_customers,write_customers',
    apiVersion: '2025-04',
    webhookSecret: process.env.SHOPIFY_WEBHOOK_SECRET
  },
  wineDirect: {
    apiKey: process.env.WINEDIRECT_API_KEY,
    apiSecret: process.env.WINEDIRECT_API_SECRET,
    baseUrl: process.env.WINEDIRECT_BASE_URL || 'https://api.winedirect.com/v1'
  },
  app: {
    port: process.env.PORT || 3000,
    environment: process.env.NODE_ENV || 'development',
    logLevel: process.env.LOG_LEVEL || 'info'
  },
  deduplication: {
    // Rules for product deduplication
    product: {
      // Confidence thresholds for matching
      nameSimilarityThreshold: 0.85, // Threshold for name similarity (0-1)
      requireSkuMatch: false, // Whether to require SKU match
      // Weights for different fields when calculating match scores
      weights: {
        sku: 0.5,
        name: 0.3,
        description: 0.1,
        price: 0.1
      }
    },
    // Rules for customer deduplication
    customer: {
      // Confidence thresholds for matching
      emailExactMatch: true, // Whether email must match exactly
      nameThreshold: 0.8, // Threshold for name similarity (0-1)
      // Weights for different fields when calculating match scores
      weights: {
        email: 0.6,
        firstName: 0.2,
        lastName: 0.2
      }
    }
  }
};

// src/utils/logger.js
/**
 * Simple logging utility
 * In a production environment, you would likely use a more robust logging solution
 * like Winston or Pino
 */

const LOG_LEVELS = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3,
};

// Set default log level from environment or default to INFO
const currentLevel = LOG_LEVELS[process.env.LOG_LEVEL?.toUpperCase()] || LOG_LEVELS.INFO;

class Logger {
  constructor() {
    this.context = null;
  }

  // Create a logger with context
  withContext(context) {
    const contextLogger = new Logger();
    contextLogger.context = context;
    return contextLogger;
  }

  _log(level, message, data = {}) {
    if (LOG_LEVELS[level] > currentLevel) {
      return;
    }

    const timestamp = new Date().toISOString();
    const context = this.context ? ` [${this.context}]` : '';
    
    const logData = typeof data === 'object' && data !== null ? data : { data };
    
    const logEntry = {
      timestamp,
      level,
      context: this.context || '',
      message,
      ...logData
    };

    // In production, you might want to format this differently or send to a logging service
    console.log(JSON.stringify(logEntry));
  }

  error(message, data = {}) {
    this._log('ERROR', message, data);
  }

  warn(message, data = {}) {
    this._log('WARN', message, data);
  }

  info(message, data = {}) {
    this._log('INFO', message, data);
  }

  debug(message, data = {}) {
    this._log('DEBUG', message, data);
  }
}

module.exports = new Logger();

// src/utils/retryWithBackoff.js
/**
 * Utility to retry a function with exponential backoff
 * Used for handling rate limits and transient network errors
 */
const logger = require('./logger');

/**
 * Executes a function with retry capability using exponential backoff
 * @param {Function} fn - The async function to execute
 * @param {Object} options - Retry options
 * @param {number} options.maxRetries - Maximum number of retry attempts (default: 5)
 * @param {number} options.baseDelay - Base delay in ms (default: 1000)
 * @param {number} options.maxDelay - Maximum delay in ms (default: 30000)
 * @param {Function} options.shouldRetry - Function that determines if retry should happen (default: retry on 429, 5xx)
 * @returns {Promise<any>} - The result of the function execution
 */
async function retryWithBackoff(fn, options = {}) {
  const {
    maxRetries = 5,
    baseDelay = 1000,
    maxDelay = 30000,
    shouldRetry = (error) => {
      // Default retry condition: retry on rate limit (429) and server errors (5xx)
      if (error.response) {
        return error.response.status === 429 || 
               (error.response.status >= 500 && error.response.status < 600);
      }
      // Also retry on network errors
      return error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT';
    }
  } = options;

  let retries = 0;
  
  while (true) {
    try {
      return await fn();
    } catch (error) {
      // Extract retry-after header if available (common in 429 responses)
      const retryAfter = error.response?.headers?.['retry-after'];
      let retryAfterMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : null;
      
      if (retries >= maxRetries || !shouldRetry(error)) {
        logger.error(`All retry attempts failed or error not retriable: ${error.message}`);
        throw error;
      }
      
      // Calculate delay with exponential backoff and jitter
      let delay;
      if (retryAfterMs) {
        // Use retry-after if available
        delay = retryAfterMs;
      } else {
        // Otherwise use exponential backoff
        delay = Math.min(
          maxDelay,
          baseDelay * Math.pow(2, retries) * (0.8 + Math.random() * 0.4) // Add jitter (±20%)
        );
      }

      logger.warn(`Request failed (attempt ${retries + 1}/${maxRetries}). Retrying in ${delay}ms. Error: ${error.message}`);
      
      await new Promise(resolve => setTimeout(resolve, delay));
      retries++;
    }
  }
}

module.exports = retryWithBackoff;

// src/utils/stringSimilarity.js
/**
 * Utilities for string comparison used in deduplication
 */

/**
 * Calculate Levenshtein distance between two strings
 * @param {string} str1 - First string
 * @param {string} str2 - Second string
 * @returns {number} - Levenshtein distance
 */
function levenshteinDistance(str1, str2) {
  const track = Array(str2.length + 1).fill(null).map(() => 
    Array(str1.length + 1).fill(null));
  
  for (let i = 0; i <= str1.length; i += 1) {
    track[0][i] = i;
  }
  
  for (let j = 0; j <= str2.length; j += 1) {
    track[j][0] = j;
  }
  
  for (let j = 1; j <= str2.length; j += 1) {
    for (let i = 1; i <= str1.length; i += 1) {
      const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
      track[j][i] = Math.min(
        track[j][i - 1] + 1, // deletion
        track[j - 1][i] + 1, // insertion
        track[j - 1][i - 1] + indicator, // substitution
      );
    }
  }
  
  return track[str2.length][str1.length];
}

/**
 * Calculate string similarity score (0-1) using Levenshtein distance
 * @param {string} str1 - First string
 * @param {string} str2 - Second string
 * @returns {number} - Similarity score between 0 and 1
 */
function stringSimilarity(str1, str2) {
  if (!str1 && !str2) return 1; // Both empty
  if (!str1 || !str2) return 0; // One empty
  
  const s1 = str1.toLowerCase();
  const s2 = str2.toLowerCase();
  
  const maxLen = Math.max(s1.length, s2.length);
  if (maxLen === 0) return 1;
  
  const distance = levenshteinDistance(s1, s2);
  return 1 - (distance / maxLen);
}

/**
 * Normalize a string by removing common punctuation, extra spaces, and lowercasing
 * @param {string} str - String to normalize
 * @returns {string} - Normalized string
 */
function normalizeString(str) {
  if (!str) return '';
  return str
    .toLowerCase()
    .replace(/[.,\/#!$%\^&\*;:{}=\-_`~()]/g, '') // Remove punctuation
    .replace(/\s+/g, ' ')                        // Replace multiple spaces with single space
    .trim();
}

module.exports = {
  stringSimilarity,
  normalizeString
};

// src/utils/errorHandling.js
/**
 * Error handling utilities
 */
const logger = require('./logger');

/**
 * Custom error class for API errors
 */
class ApiError extends Error {
  constructor(message, statusCode, source, details = {}) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.source = source;
    this.details = details;
  }
}

/**
 * Safely execute a function and handle errors without crashing
 * @param {Function} fn - Async function to execute
 * @param {string} operation - Name of the operation for logging
 * @param {Function} [onError] - Optional error handler
 * @returns {Promise<Object>} - Result object with success flag and data/error
 */
async function safeExecute(fn, operation, onError) {
  try {
    const data = await fn();
    return { success: true, data };
  } catch (error) {
    logger.error(`Error during ${operation}`, {
      error: error.message,
      stack: error.stack,
      details: error.details || {}
    });
    
    if (onError && typeof onError === 'function') {
      await onError(error);
    }
    
    return { 
      success: false, 
      error: {
        message: error.message,
        statusCode: error.statusCode,
        source: error.source,
        details: error.details
      }
    };
  }
}

module.exports = {
  ApiError,
  safeExecute
};

// src/api/shopify/auth.js
/**
 * Shopify OAuth2 authentication implementation
 */
const axios = require('axios');
const crypto = require('crypto');
const querystring = require('querystring');
const logger = require('../../utils/logger').withContext('ShopifyAuth');
const config = require('../../config');

class ShopifyAuth {
  constructor() {
    this.clientId = config.shopify.clientId;
    this.clientSecret = config.shopify.clientSecret;
    this.redirectUri = config.shopify.redirectUri;
    this.scopes = config.shopify.scopes;
  }

  /**
   * Generate authorization URL for OAuth flow
   * @param {string} shop - Shop name (e.g., my-store.myshopify.com)
   * @param {string} state - Random state parameter for CSRF protection
   * @returns {string} - Authorization URL
   */
  getAuthorizationUrl(shop, state) {
    const queryParams = querystring.stringify({
      client_id: this.clientId,
      scope: this.scopes,
      redirect_uri: this.redirectUri,
      state: state,
      grant_options: ['per-user'] // Request online access mode
    });

    return `https://${shop}/admin/oauth/authorize?${queryParams}`;
  }

  /**
   * Verify the state parameter to prevent CSRF attacks
   * @param {string} originalState - The state we generated in the authorization request
   * @param {string} returnedState - The state returned in the callback
   * @returns {boolean} - Whether the state is valid
   */
  verifyState(originalState, returnedState) {
    return originalState === returnedState;
  }

  /**
   * Verify the HMAC signature sent by Shopify
   * @param {Object} query - Query parameters from the request
   * @returns {boolean} - Whether the HMAC is valid
   */
  verifyHmac(query) {
    const hmac = query.hmac;
    const message = Object.keys(query)
      .filter(key => key !== 'hmac')
      .sort()
      .map(key => `${key}=${query[key]}`)
      .join('&');

    const generatedHash = crypto
      .createHmac('sha256', this.clientSecret)
      .update(message)
      .digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(generatedHash, 'hex'),
      Buffer.from(hmac, 'hex')
    );
  }

  /**
   * Exchange authorization code for access token
   * @param {string} shop - Shop name (e.g., my-store.myshopify.com)
   * @param {string} code - Authorization code from callback
   * @returns {Promise<Object>} - Access token response
   */
  async getAccessToken(shop, code) {
    try {
      const response = await axios.post(`https://${shop}/admin/oauth/access_token`, {
        client_id: this.clientId,
        client_secret: this.clientSecret,
        code
      });

      // The response includes access_token, scope, and for offline access: refresh_token
      logger.info('Successfully retrieved Shopify access token');
      return response.data;
    } catch (error) {
      logger.error('Failed to get Shopify access token', {
        error: error.message,
        statusCode: error.response?.status
      });
      throw new Error(`Failed to get access token: ${error.message}`);
    }
  }

  /**
   * Refresh an access token (only needed for offline tokens with expiry)
   * Note: Standard Shopify access tokens don't expire unless revoked,
   * but this may change in the future or with specific configurations
   * @param {string} refreshToken - The refresh token
   * @returns {Promise<Object>} - New token response
   */
  async refreshToken(refreshToken) {
    try {
      const response = await axios.post('https://shopify.com/oauth/access_token', {
        client_id: this.clientId,
        client_secret: this.clientSecret,
        grant_type: 'refresh_token',
        refresh_token: refreshToken
      });

      logger.info('Successfully refreshed Shopify access token');
      return response.data;
    } catch (error) {
      logger.error('Failed to refresh Shopify access token', {
        error: error.message,
        statusCode: error.response?.status
      });
      throw new Error(`Failed to refresh access token: ${error.message}`);
    }
  }
}

module.exports = new ShopifyAuth();

// src/api/shopify/client.js
/**
 * Shopify API client with support for:
 * - Authentication
 * - Pagination
 * - Rate limiting with exponential backoff
 */
const axios = require('axios');
const logger = require('../../utils/logger').withContext('ShopifyClient');
const retryWithBackoff = require('../../utils/retryWithBackoff');
const config = require('../../config');

class ShopifyClient {
  /**
   * Create a new Shopify API client instance
   * @param {string} shop - Shop name (e.g., my-store.myshopify.com)
   * @param {string} accessToken - OAuth access token
   */
  constructor(shop, accessToken) {
    this.shop = shop;
    this.accessToken = accessToken;
    this.apiVersion = config.shopify.apiVersion;
    
    // Initialize axios instance with default config
    this.client = axios.create({
      baseURL: `https://${shop}/admin/api/${this.apiVersion}`,
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': accessToken
      },
      timeout: 10000 // 10 seconds
    });
  }

  /**
   * Make an API request with retry capabilities
   * @param {string} method - HTTP method
   * @param {string} endpoint - API endpoint
   * @param {Object} [data=null] - Request payload for POST/PUT
   * @param {Object} [params={}] - URL parameters
   * @returns {Promise<Object>} - API response
   */
  async request(method, endpoint, data = null, params = {}) {
    const requestFn = async () => {
      try {
        const response = await this.client({
          method,
          url: endpoint,
          data,
          params
        });
        
        return response.data;
      } catch (error) {
        // Enhance error with additional context
        if (error.response) {
          error.message = `Shopify API error (${error.response.status}): ${
            error.response.data?.errors || error.message
          }`;
        }
        throw error;
      }
    };

    // Configure retry options specifically for Shopify
    const retryOptions = {
      maxRetries: 5,
      baseDelay: 1000,
      maxDelay: 30000,
      shouldRetry: (error) => {
        // Retry on rate limits, server errors, and specific Shopify throttling errors
        if (error.response) {
          const status = error.response.status;
          const shopifyRetryable = 
            status === 429 || // Too Many Requests
            status === 430 || // Shopify API unavailable
            (status >= 500 && status < 600); // Server errors
          
          if (shopifyRetryable) {
            return true;
          }
          
          // Check for specific throttling errors in the body
          const errorMessage = error.response.data?.errors;
          if (typeof errorMessage === 'string' && 
              (errorMessage.includes('throttled') || 
               errorMessage.includes('exceeded') ||
               errorMessage.includes('too many requests'))) {
            return true;
          }
        }
        
        // Network errors
        return error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT';
      }
    };

    return retryWithBackoff(requestFn, retryOptions);
  }

  /**
   * Fetch all resources with automatic pagination handling
   * Supports both REST and GraphQL pagination styles
   * @param {string} method - HTTP method
   * @param {string} endpoint - API endpoint
   * @param {Object} [params={}] - URL parameters
   * @param {string} [dataPath=''] - Path to data array in response
   * @returns {Promise<Array>} - All resources
   */
  async fetchAll(method, endpoint, params = {}, dataPath = '') {
    let allData = [];
    let nextPageUrl = null;
    let page = 1;
    const initialParams = { ...params, limit: 250 }; // Max page size for most endpoints
    
    try {
      do {
        // For first page, use endpoint with params; for subsequent pages, use next_page URL
        let response;
        if (nextPageUrl) {
          // Remove the domain from the next_page URL
          const parsedUrl = new URL(nextPageUrl);
          const pathWithQuery = parsedUrl.pathname + parsedUrl.search;
          response = await this.request('GET', pathWithQuery.replace(`/admin/api/${this.apiVersion}`, ''));
        } else {
          response = await this.request(method, endpoint, null, initialParams);
        }

        // Extract data based on the provided path
        let pageData;
        if (dataPath) {
          // Handle nested data paths like 'products.edges'
          pageData = dataPath.split('.').reduce((obj, path) => obj && obj[path], response) || [];
        } else {
          // For top-level arrays
          const key = Object.keys(response).find(k => Array.isArray(response[k]));
          pageData = key ? response[key] : [];
        }

        // Add this page's data to the result
        allData = allData.concat(pageData);
        
        // Check for next page - Shopify provides it in Link header or in response body
        nextPageUrl = null;
        
        // REST pagination: look for next_page URL in response
        if (response.next_page) {
          nextPageUrl = response.next_page;
        } 
        // REST pagination: look for pagination info
        else if (response.links?.next) {
          nextPageUrl = response.links.next;
        }
        // GraphQL pagination: check for hasNextPage and use cursor
        else if (response.pageInfo?.hasNextPage && pageData.length > 0) {
          const lastCursor = pageData[pageData.length - 1].cursor;
          if (lastCursor) {
            // For GraphQL, we'll reuse the same endpoint but update the after parameter
            initialParams.after = lastCursor;
            // No nextPageUrl, but we'll continue the loop
            nextPageUrl = 'continue';
          }
        }
        
        logger.debug(`Fetched page ${page} from ${endpoint}, got ${pageData.length} items`);
        page++;
        
      } while (nextPageUrl);

      logger.info(`Successfully fetched all ${allData.length} items from ${endpoint}`);
      return allData;
    } catch (error) {
      logger.error(`Failed to fetch all data from ${endpoint}`, { error: error.message });
      throw error;
    }
  }

  /**
   * GET request wrapper
   * @param {string} endpoint - API endpoint
   * @param {Object} [params={}] - URL parameters
   * @returns {Promise<Object>} - API response
   */
  async get(endpoint, params = {}) {
    return this.request('GET', endpoint, null, params);
  }

  /**
   * POST request wrapper
   * @param {string} endpoint - API endpoint
   * @param {Object} data - Request payload
   * @param {Object} [params={}] - URL parameters
   * @returns {Promise<Object>} - API response
   */
  async post(endpoint, data, params = {}) {
    return this.request('POST', endpoint, data, params);
  }

  /**
   * PUT request wrapper
   * @param {string} endpoint - API endpoint
   * @param {Object} data - Request payload
   * @param {Object} [params={}] - URL parameters
   * @returns {Promise<Object>} - API response
   */
  async put(endpoint, data, params = {}) {
    return this.request('PUT', endpoint, data, params);
  }

  /**
   * DELETE request wrapper
   * @param {string} endpoint - API endpoint
   * @param {Object} [params={}] - URL parameters
   * @returns {Promise<Object>} - API response
   */
  async delete(endpoint, params = {}) {
    return this.request('DELETE', endpoint, null, params);
  }
}

module.exports = ShopifyClient;

// src/api/shopify/products.js
/**
 * Shopify product fetching and normalization
 */
const logger = require('../../utils/logger').withContext('ShopifyProducts');

class ShopifyProducts {
  /**
   * Create a new Shopify Products handler
   * @param {ShopifyClient} client - Initialized Shopify client
   */
  constructor(client) {
    this.client = client;
  }

  /**
   * Fetch all products from Shopify
   * @param {Object} [options={}] - Fetch options
   * @param {number} [options.limit] - Maximum number of products to fetch
   * @param {string} [options.updatedAtMin] - Only fetch products updated after this timestamp
   * @returns {Promise<Array>} - Normalized product data
   */
  async fetchProducts(options = {}) {
    try {
      const params = {};
      
      if (options.limit) {
        params.limit = options.limit;
      }
      
      if (options.updatedAtMin) {
        params.updated_at_min = options.updatedAtMin;
      }
      
      logger.info('Fetching products from Shopify', { params });
      
      // Use the fetchAll method from our client to handle pagination
      const products = await this.client.fetchAll('GET', '/products.json', params, 'products');
      
      logger.info(`Successfully fetched ${products.length} products from Shopify`);
      
      // Normalize the products to our standard format
      return this.normalizeProducts(products);
    } catch (error) {
      logger.error('Failed to fetch products from Shopify', { 
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Normalize Shopify product data to our standard format
   * @param {Array} products - Raw product data from Shopify
   * @returns {Array} - Normalized product data
   */
  normalizeProducts(products) {
    return products.map(product => {
      // Extract variants as separate products if they exist
      const variants = product.variants || [];
      
      if (variants.length === 0) {
        // No variants, just normalize the product
        return this.normalizeSingleProduct(product);
      }
      
      // If there are variants, normalize each as a separate product
      return variants.map(variant => {
        return this.normalizeVariantAsProduct(product, variant);
      });
    }).flat(); // Flatten the array of arrays
  }

  /**
   * Normalize a single Shopify product without variants
   * @param {Object} product - Raw product data
   * @returns {Object} - Normalized product
   */
  normalizeSingleProduct(product) {
    // Get the main image URL if available
    const mainImage = product.images && product.images.length > 0 
      ? product.images[0].src 
      : null;
    
    return {
      id: `shopify_${product.id}`,
      source: 'shopify',
      sourceId: product.id.toString(),
      sku: product.variants && product.variants[0] ? product.variants[0].sku : null,
      title: product.title,
      description: product.body_html,
      price: product.variants && product.variants[0] ? 
        parseFloat(product.variants[0].price) : 0,
      compareAtPrice: product.variants && product.variants[0] && product.variants[0].compare_at_price ? 
        parseFloat(product.variants[0].compare_at_price) : null,
      imageUrl: mainImage,
      inventoryQuantity: product.variants && product.variants[0] ? 
        product.variants[0].inventory_quantity : 0,
      published: product.published_at !== null,
      tags: product.tags ? product.tags.split(', ') : [],
      vendor: product.vendor,
      type: product.product_type,
      handle: product.handle,
      createdAt: product.created_at,
      updatedAt: product.updated_at
    };
  }

  /**
   * Normalize a product variant as a standalone product
   * @param {Object} product - Raw product data
   * @param {Object} variant - Product variant data
   * @returns {Object} - Normalized product
   */
  normalizeVariantAsProduct(product, variant) {
    // Find variant-specific image if it exists
    let variantImage = null;
    
    if (variant.image_id && product.images) {
      const matchingImage = product.images.find(img => img.id === variant.image_id);
      if (matchingImage) {
        variantImage = matchingImage.src;
      }
    }
    
    // Fall back to main product image if no variant-specific image
    if (!variantImage && product.images && product.images.length > 0) {
      variantImage = product.images[0].src;
    }
    
    // Create option details string
    const optionDetails = [];
    if (variant.option1) optionDetails.push(variant.option1);
    if (variant.option2) optionDetails.push(variant.option2);
    if (variant.option3) optionDetails.push(variant.option3);
    
    const variantTitle = optionDetails.length > 0 
      ? `${product.title} - ${optionDetails.join(' / ')}` 
      : product.title;
    
    return {
      id: `shopify_${variant.product_id}_${variant.id}`,
      source: 'shopify',
      sourceId: variant.id.toString(),
      parentId: `shopify_${product.id}`,
      sku: variant.sku || null,
      title: variantTitle,
      description: product.body_html,
      price: parseFloat(variant.price),
      compareAtPrice: variant.compare_at_price ? parseFloat(variant.compare_at_price) : null,
      imageUrl: variantImage,
      inventoryQuantity: variant.inventory_quantity || 0,
      published: product.published_at !== null && !variant.inventory_policy?.includes('deny'),
      tags: product.tags ? product.tags.split(', ') : [],
      vendor: product.vendor,
      type: product.product_type,
      handle: product.handle,
      variantOptions: optionDetails,
      barcode: variant.barcode,
      weight: variant.weight,
      weightUnit: variant.weight_unit,
      requiresShipping: variant.requires_shipping,
      createdAt: variant.created_at || product.created_at,
      updatedAt: variant.updated_at || product.updated_at
    };
  }
}

module.exports = ShopifyProducts;

// src/api/shopify/customers.js
/**
 * Shopify customer fetching and normalization
 */
const logger = require('../../utils/logger').withContext('ShopifyCustomers');

class ShopifyCustomers {
  /**
   * Create a new Shopify Customers handler
   * @param {ShopifyClient} client - Initialized Shopify client
   */
  constructor(client) {
    this.client = client;
  }

  /**
   * Fetch all customers from Shopify
   * @param {Object} [options={}] - Fetch options
   * @param {number} [options.limit] - Maximum number of customers to fetch
   * @param {string} [options.updatedAtMin] - Only fetch customers updated after this timestamp
   