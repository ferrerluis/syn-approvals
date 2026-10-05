module.exports = ({ config }) => ({
  ...config,
  ios: { ...config.ios, bundleIdentifier: process.env.SYN_MOBILE_VARIANT === 'production'
    ? 'org.syn-approvals.SynMobile' : 'org.syn-approvals.SynMobile.Debug' },
});
