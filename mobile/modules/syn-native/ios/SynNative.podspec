Pod::Spec.new do |s|
  s.name = 'SynNative'
  s.version = '0.1.0'
  s.summary = 'Request-bound direct Syn approval bridge'
  s.description = 'Native verification and one-invocation approvals for Syn.'
  s.license = { :type => 'MIT' }
  s.author = 'Syn'
  s.homepage = 'https://github.com/ferrerluis/syn-approvals'
  s.platforms = { :ios => '18.0' }
  s.source = { :git => 'https://github.com/ferrerluis/syn-approvals' }
  s.static_framework = true
  s.dependency 'ExpoModulesCore'
  s.vendored_frameworks = 'Frameworks/SynMobileCore.xcframework'
  s.source_files = 'src/**/*.swift'
  s.swift_version = '5.9'
end
