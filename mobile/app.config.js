const { expo } = require('./app.json');
module.exports = () => ({
  ...expo,
  ios: { ...expo.ios, bundleIdentifier: process.env.SYN_MOBILE_VARIANT === 'production'
    ? 'org.syn-approvals.SynMobile' : 'org.syn-approvals.SynMobile.Debug' },
});
