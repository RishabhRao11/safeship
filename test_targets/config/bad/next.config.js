// Next.js config, planted fixture.
module.exports = {
  images: {
    dangerouslyAllowSVG: true,
    remotePatterns: [{ protocol: 'https', hostname: '**' }],
  },
  async headers() {
    return [{ source: '/api/:path*', headers: [
      { key: 'Access-Control-Allow-Origin', value: '*' },
    ]}];
  },
};
