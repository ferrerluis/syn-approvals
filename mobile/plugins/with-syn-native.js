const { withXcodeProject, withAppDelegate, IOSConfig } = require('expo/config-plugins');
const fs = require('fs');
const path = require('path');
module.exports = function withSynNative(config) {
  config = withXcodeProject(config, c => {
    const project = c.modResults;
    for (const phase of Object.values(project.hash.project.objects.PBXShellScriptBuildPhase)) {
      if (typeof phase !== 'object' || phase.name !== '"Bundle React Native code and images"') continue;
      const script = JSON.parse(phase.shellScript);
      const marker = 'if [[ "$CONFIGURATION" = *Debug* ]]; then';
      if (!script.includes(marker)) throw new Error('Unsupported Expo bundling phase.');
      phase.shellScript = JSON.stringify(script.replace(marker,
        'if [[ "$CONFIGURATION" = *Debug* && -z "$FORCE_BUNDLING" ]]; then'));
    }
    for (const item of Object.values(project.pbxXCBuildConfigurationSection())) {
      if (typeof item !== 'object' || item.name !== 'Debug' || !item.buildSettings.PRODUCT_BUNDLE_IDENTIFIER) continue;
      item.buildSettings['"CODE_SIGN_ENTITLEMENTS[sdk=iphonesimulator*]"'] = '"../scripts/Simulator.entitlements"';
    }
    const file = 'Syn/release.json';
    const location = path.join(c.modRequest.platformProjectRoot, file);
    fs.mkdirSync(path.dirname(location), { recursive: true });
    fs.copyFileSync(path.join(c.modRequest.projectRoot, '../ios/Support/release.json'), location);
    IOSConfig.XcodeUtils.addResourceFileToGroup({ filepath: file, groupName: 'Syn', isBuildFile: true, project });
    return c;
  });
  return withAppDelegate(config, c => {
    // Acceptance Debug builds embed JS while retaining the simulator-only signer.
    const content = c.modResults.contents;
    const marker = '#if DEBUG';
    if (!content.includes(marker)) throw new Error('Unsupported Expo AppDelegate; cannot enforce embedded acceptance JS.');
    c.modResults.contents = content.replace(marker,
      '#if SYN_EMBEDDED_BUNDLE\n    return Bundle.main.url(forResource: "main", withExtension: "jsbundle")\n    #elseif DEBUG');
    return c;
  });
};
