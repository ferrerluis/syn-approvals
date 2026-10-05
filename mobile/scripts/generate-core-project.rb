require 'xcodeproj'
require 'fileutils'
root = File.expand_path('..', __dir__)
repo = File.dirname(root)
out = File.join(root, 'native-build')
FileUtils.mkdir_p(out)
project = Xcodeproj::Project.new(File.join(out, 'SynMobileCore.xcodeproj'))
target = project.new_target(:framework, 'SynMobileCore', :ios, '18.0')
shared = %w[CBOR SynProtocol SafeDisplay DecisionBuilder KeyStore Transport TargetStore ReleaseIdentity]
paths = shared.map { |n| File.join(repo, 'macos/Sources/Syn', n + '.swift') }
paths += %w[IOSModel IOSSigning MobileSSH IOSSSHMetadata IOSTransportIdentityStore].map { |n| File.join(repo, 'ios/Sources', n + '.swift') }
paths << File.join(root, 'native-core/SynMobileService.swift')
# Hide implementation dependencies from the framework's public Swift module.
# The Expo facade exposes only Foundation values; all package code is linked here.
implementation_dir = File.join(out, 'sources')
FileUtils.mkdir_p(implementation_dir)
paths.each do |path|
  text = File.read(path).gsub(/^(@preconcurrency )?import (NIOCore|NIOPosix|NIOSSH|X509|SwiftASN1)$/, '\1internal import \2')
  copy = File.join(implementation_dir, File.basename(path))
  File.write(copy, text)
  target.source_build_phase.add_file_reference(project.main_group.new_file(copy))
end
original = Xcodeproj::Project.open(File.join(repo, 'ios/SynIOS.xcodeproj'))
original.root_object.package_references.each do |reference|
  newref = project.new(Xcodeproj::Project::Object::XCRemoteSwiftPackageReference)
  newref.repositoryURL = reference.repositoryURL
  newref.requirement = reference.requirement
  project.root_object.package_references << newref
  original.native_targets.first.package_product_dependencies.select { |p| p.package == reference }.each do |p|
    dependency = project.new(Xcodeproj::Project::Object::XCSwiftPackageProductDependency)
    dependency.package = newref
    dependency.product_name = p.product_name
    target.package_product_dependencies << dependency
    file = project.new(Xcodeproj::Project::Object::PBXBuildFile)
    file.product_ref = dependency
    target.frameworks_build_phase.files << file
  end
end
target.build_configurations.each do |config|
  config.build_settings.merge!({ 'PRODUCT_BUNDLE_IDENTIFIER' => 'org.syn-approvals.SynMobileCore', 'SWIFT_VERSION' => '6.0', 'SWIFT_TREAT_WARNINGS_AS_ERRORS' => 'YES', 'SKIP_INSTALL' => 'NO', 'DEFINES_MODULE' => 'YES', 'GENERATE_INFOPLIST_FILE' => 'YES', 'CODE_SIGNING_ALLOWED' => 'NO', 'BUILD_LIBRARY_FOR_DISTRIBUTION' => 'YES' })
  config.build_settings['SWIFT_ACTIVE_COMPILATION_CONDITIONS'] = config.name == 'Debug' ? 'DEBUG' : ''
end
project.save
resolved_dir = File.join(project.path, 'project.xcworkspace/xcshareddata/swiftpm')
FileUtils.mkdir_p(resolved_dir)
FileUtils.cp(File.join(repo, 'ios/SynIOS.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved'), File.join(resolved_dir, 'Package.resolved'))
scheme = Xcodeproj::XCScheme.new
scheme.add_build_target(target)
scheme.save_as(project.path, 'SynMobileCore', true)
