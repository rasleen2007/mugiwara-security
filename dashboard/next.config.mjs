/** @type {import('next').NextConfig} */
const nextConfig = {
  // Fail clearly when the API URL is missing at build time.
  // NEXT_PUBLIC_* vars are statically inlined at build time.
  // The runtime check in api-client.ts handles development.
  reactStrictMode: true,
};

export default nextConfig;
