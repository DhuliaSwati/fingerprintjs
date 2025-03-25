const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// Initialize Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// Configure rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' }
});

// AES encryption function
function encryptData(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return {
    encrypted: encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

// Validate required fields
function validateFingerprint(data) {
  const requiredFields = ['shopId', 'sessionId', 'browserData'];
  for (const field of requiredFields) {
    if (!data[field]) {
      throw new Error(`Missing required field: ${field}`);
    }
  }
}

// Extract TLS data from headers
function extractTlsData(headers) {
  return {
    version: headers['ssl-protocol'] || headers['x-forwarded-proto'],
    cipher: headers['ssl-cipher'],
    userAgent: headers['user-agent'],
    acceptLanguage: headers['accept-language'],
    acceptEncoding: headers['accept-encoding'],
    // Additional headers for fingerprinting
    secChUa: headers['sec-ch-ua'],
    secChUaPlatform: headers['sec-ch-ua-platform'],
    secChMobile: headers['sec-ch-ua-mobile']
  };
}

// Main handler function
export default async function handler(req, res) {
  try {
    // Apply rate limiting
    await new Promise((resolve) => limiter(req, res, resolve));
    
    // Only accept POST requests
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
    
    // Extract data from request
    const {
      shopId,
      sessionId,
      browserData,
      webglData,
      screenData,
      audioData,
      networkData,
      // Additional optional data
      deviceMemory,
      hardwareConcurrency,
      timezone,
      plugins,
      touchPoints,
      inputTypes
    } = req.body;
    
    // Validate required fields
    validateFingerprint(req.body);
    
    // Get IP and TLS data
    const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const tlsData = extractTlsData(req.headers);
    
    // Generate fingerprint hash
    const fingerprintData = {
      browserData,
      webglData,
      screenData,
      tlsData,
      ipAddress,
      // Include all collected data points
      deviceData: {
        memory: deviceMemory,
        cores: hardwareConcurrency,
        timezone,
        plugins,
        touchPoints,
        inputTypes
      },
      networkData,
      audioData
    };
    
    // Create hash of fingerprint data
    const fingerprintHash = crypto
      .createHash('sha256')
      .update(JSON.stringify(fingerprintData))
      .digest('hex');
    
    // Encrypt sensitive data
    const encryptedData = encryptData(
      fingerprintData,
      process.env.ENCRYPTION_KEY
    );
    
    // Store in Supabase
    const { data, error } = await supabase
      .from('fingerprints')
      .insert({
        shop_id: shopId,
        session_id: sessionId,
        fingerprint_hash: fingerprintHash,
        ip_address: ipAddress,
        tls_version: tlsData.version,
        tls_cipher: tlsData.cipher,
        user_agent: tlsData.userAgent,
        encrypted_data: encryptedData.encrypted,
        encryption_iv: encryptedData.iv,
        encryption_tag: encryptedData.authTag,
        browser_data: browserData,
        webgl_data: webglData,
        screen_data: screenData,
        created_at: new Date().toISOString(),
        last_seen: new Date().toISOString()
      })
      .select('id, fingerprint_hash');
    
    if (error) {
      console.error('Supabase error:', error);
      return res.status(500).json({ error: 'Failed to store fingerprint' });
    }
    
    // Return minimal data to client
    return res.status(200).json({
      success: true,
      fingerprintId: data[0].id,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Fingerprint collection error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
}