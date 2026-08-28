// Correctly configured Next.js. Zero findings expected.
module.exports = {
  images: {
    remotePatterns: [{ protocol: 'https', hostname: 'cdn.example.com' }],
  },
  async headers() {
    return [{ source: '/api/:path*', headers: [
      { key: 'Access-Control-Allow-Origin', value: 'https://app.example.com' },
    ]}];
  },
};
