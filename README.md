# IP Grabber

A self-hosted IP logging service with automatic redirection capabilities.

## Features

- Public and local IP address collection
- Geolocation data (country, city, ISP)
- Browser fingerprinting
- Connection details and network information
- Web-based admin dashboard with password protection
- Configurable redirect URLs
- Silent operation with blank page interface

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

## Admin Access

The admin dashboard is protected by password authentication:

- **Default password:** `admin`
- Access the dashboard at `/admin` and enter the password
- Password can be changed by modifying `adminPassword` in `config.json`

## How It Works

1. Visitor accesses the main page
2. JavaScript silently collects visitor information
3. Data is logged to the server
4. User is automatically redirected to configured destination

## Data Collected

- IP addresses (public and local)
- Geographic location
- Browser and system information
- Screen resolution and display details
- Network connection details
- Timestamp and referrer information


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

## Technical Requirements

- Node.js 16+
- Modern web browser with JavaScript enabled
- HTTPS recommended for full functionality

## License

This project is for educational purposes. Users are responsible for compliance with applicable laws and regulations regarding data collection and privacy.