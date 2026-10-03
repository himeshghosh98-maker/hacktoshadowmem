/** @type {import('next').NextConfig} */
const isDev = process.env.NODE_ENV !== 'production';

const nextConfig = {
  // During build / production, export static HTML/JS/CSS without requiring a Node server
  output: isDev ? undefined : 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  // Dev-server API proxy only during local next dev
  ...(isDev
    ? {
        async rewrites() {
          return [
            {
              source: '/api/:path*',
              destination: 'http://127.0.0.1:8000/api/:path*',
            },
            {
              source: '/simulate/:path*',
              destination: 'http://127.0.0.1:8000/simulate/:path*',
            },
          ];
        },
      }
    : {}),
};

export default nextConfig;
