# IP Grabber

A self-hosted IP logging service with automatic redirection capabilities.

## Features

- **Advanced IP Detection**: Public and local IP address collection with real IP extraction from proxy headers
- **Social Media Proxy Detection**: Identifies traffic from Instagram, Facebook, Twitter, LinkedIn, Discord, TikTok, Telegram, WhatsApp, and Snapchat
- **Dual IP Tracking**: Separates proxy/CDN IPs from real client IPs with confidence scoring
- **Platform Identification**: Distinguishes between direct browser access, in-app browsers, and proxy services
- **Enhanced Geolocation**: Multiple location sources (client-side, real IP, proxy IP) with intelligent prioritization
- **Browser Fingerprinting**: Comprehensive device and browser detection
- **Admin Dashboard**: Password-protected web interface with color-coded platform badges and dual IP display
- **Real-time Logging**: Live visitor tracking with platform-specific categorization
- **Configurable Settings**: Customizable redirect URLs and site configuration
- **Silent Operation**: Invisible data collection with automatic redirection

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the server:
   ```bash
   npm start
   ```

## Usage

- Main page: `http://localhost:3000/`
- Admin dashboard: `http://localhost:3000/admin` (password required)
- API endpoints: `http://localhost:3000/admin/logs`

## Admin Dashboard

The enhanced admin dashboard provides comprehensive visitor analytics with advanced proxy detection:

### Authentication
- **Default password:** `admin`
- Access the dashboard at `/admin` and enter the password
- **Security Features**: Session management with automatic logout, password change capability

### Dashboard Features
- **Platform Identification**: Color-coded badges showing visitor source (Instagram, Facebook, Twitter, etc.)
- **Dual IP Display**: Shows both real client IP (green) and proxy IP (orange) when applicable
- **Location Intelligence**: Prioritizes real location over proxy location data
- **Real-time Statistics**: Total visits, daily counts, and unique IP tracking
- **Enhanced Filtering**: Platform-specific visitor categorization and confidence levels

### Platform Badge Colors
- 🔵 **Direct** (Blue): Regular browser traffic
- 🟡 **Proxy** (Yellow): Generic proxy or VPN traffic  
- 🔵 **Social** (Teal): Social media platform proxies
- 🟣 **In-App** (Purple): Social media in-app browsers

## How It Works

1. **Visitor Access**: User opens the main page or clicks a shared link
2. **Platform Detection**: Server analyzes IP ranges, user agents, and referrer headers to identify social media platforms
3. **IP Extraction**: Real client IP is extracted from proxy headers while preserving proxy information
4. **Data Collection**: JavaScript silently gathers client-side information (browser, location, device details)
5. **Dual Geolocation**: Server performs geolocation lookups for both real and proxy IPs
6. **Intelligent Logging**: Data is categorized by platform with confidence scoring and stored with enhanced metadata
7. **Dashboard Display**: Admin interface shows color-coded platform badges and dual IP information
8. **Automatic Redirect**: User is seamlessly redirected to the configured destination URL

### Proxy Detection Algorithm

The system uses a multi-layered approach to identify social media traffic:

- **IP Range Analysis**: Detects Facebook/Meta infrastructure (Instagram, WhatsApp) by IPv4/IPv6 ranges
- **Referrer Matching**: Identifies platform-specific domains (t.co, lnkd.in, etc.)
- **User Agent Analysis**: Recognizes in-app browsers and platform-specific crawlers
- **Header Inspection**: Extracts real client IPs from standard proxy headers
- **Confidence Scoring**: Assigns reliability levels based on detection method strength

## Data Collected

### IP Information
- **Real Client IP**: Extracted from proxy headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)
- **Proxy/Server IP**: CDN or social media proxy infrastructure IPs
- **Local Network IP**: Internal network addresses when available

### Platform Detection
- **Social Media Platforms**: Instagram, Facebook, Twitter, LinkedIn, Discord, TikTok, Telegram, WhatsApp, Snapchat
- **Proxy Classification**: Distinguishes between social media proxies, generic proxies, and in-app browsers
- **Confidence Scoring**: High/Medium/Low confidence levels for platform identification
- **Access Method**: Direct browser, in-app browser, or proxy service detection

### Location Data
- **Multi-Source Geolocation**: Client-side, real IP, and proxy IP locations
- **Geographic Details**: Country, region, city, timezone, coordinates
- **ISP Information**: Internet service provider and organization data
- **Network Details**: ASN (Autonomous System Number) and hosting information

### Device & Browser Information
- **Browser Fingerprinting**: User agent, browser type, version
- **System Details**: Operating system, device type, screen resolution
- **Network Capabilities**: Connection type and performance metrics
- **Referrer Data**: Source website and navigation path


## Configuration

The redirect URL and other settings can be configured through the admin dashboard at `/admin`. Click the "Settings" button to modify:

- Redirect destination URL
- Site name
- Clear visitor logs

### Security Configuration

For security, change the default password by editing `config.json`:

```json
{
  "adminPassword": "your-secure-password",
  "redirectUrl": "https://example.com/",
  "siteName": "IP Logger"
}
```

## Supported Platforms

### Social Media Platforms (Proxy Detection)
| Platform | Detection Method | Confidence | Proxy Type |
|----------|------------------|------------|------------|
| **Instagram** | IP ranges + User agent | High | Facebook/Meta Infrastructure |
| **Facebook** | IP ranges + Referrer | High | Facebook/Meta Infrastructure |
| **Twitter/X** | Referrer (t.co) | High | Twitter Link Wrapper |
| **LinkedIn** | Referrer (lnkd.in) | High | LinkedIn Link Shortener |
| **Discord** | User agent + IP | Medium | Discord Link Scanner |
| **TikTok** | User agent + Referrer | Medium | TikTok Link Scanner |
| **Telegram** | User agent + Referrer | Medium | Telegram Link Preview |
| **WhatsApp** | User agent + IP ranges | High | WhatsApp Link Preview |

### In-App Browsers (Direct Detection)
| Platform | Detection Method | Confidence | Browser Type |
|----------|------------------|------------|--------------|
| **Instagram** | User agent (Instagram) | High | Instagram In-App Browser |
| **Facebook** | User agent (FBAN/FBAV) | High | Facebook In-App Browser |
| **Snapchat** | User agent (Snapchat) | High | Snapchat In-App Browser |

## Version History

### v1.4.0 - Social Media Proxy Detection
- ✅ Advanced proxy detection for Instagram, Facebook, Twitter, LinkedIn, Discord, TikTok, Telegram, WhatsApp, Snapchat
- ✅ Real IP extraction from X-Forwarded-For, X-Real-IP, CF-Connecting-IP headers
- ✅ Platform identification with confidence scoring and proxy type classification
- ✅ Enhanced admin dashboard with color-coded platform badges and dual IP display
- ✅ Intelligent location prioritization (client > real IP > proxy location)
- ✅ In-app browser detection separate from proxy traffic

## Technical Requirements

- **Runtime**: Node.js 16+ with Express.js framework
- **Client**: Modern web browser with JavaScript enabled
- **Network**: HTTPS recommended for full geolocation functionality
- **APIs**: Multiple IP geolocation services (ip-api.com, ipapi.co, ipgeolocation.io)
- **Storage**: Local JSON file storage for visitor logs and configuration

## License

This project is for educational purposes. Users are responsible for compliance with applicable laws and regulations regarding data collection and privacy.